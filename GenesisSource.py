from Source import Source
from binascii import hexlify, unhexlify
import hashlib
from json import dumps, loads
from log import say_exception, say_line
from struct import pack
from threading import Thread, Lock, Timer
from time import sleep, time
from util import chunks, Object
import asynchat
import asyncore
import socket
import socks
import struct
from construct import *


#import ssl


BASE_DIFFICULTY = 0x00000000FFFF0000000000000000000000000000000000000000000000000000


class GenesisSource(Source):
	def __init__(self, switch):
		super(GenesisSource, self).__init__(switch)
		self.handler = None
		self.socket = None
		self.channel_map = {}
		self.subscribed = False
		self.authorized = None
		self.submits = {}
		self.last_submits_cleanup = time()
		self.server_difficulty = BASE_DIFFICULTY
		self.jobs = {}
		self.current_job = None
		self.extranonce = ''
		self.extranonce2_size = 4
		self.send_lock = Lock()
		self.merkle_root = ''

		self.bits = ''

	def loop(self):
		super(GenesisSource, self).loop()

		self.switch.update_time = False

		while True:
			if self.should_stop: return



			miner = self.switch.updatable_miner()
			while miner:
				self.current_job = self.refresh_job(self.current_job)

				self.queue_work(self.current_job, miner)

				miner = self.switch.updatable_miner()

			if not self.handler:
				try:


					self.handler = Handler(self.channel_map, self)
					thread = Thread(target=self.asyncore_thread)
					thread.daemon = True
					thread.start()

					if not self.subscribe():
						say_line('Failed to subscribe')
						self.stop()
					elif not self.authorize():
						self.stop()

				except socket.error:
					say_exception()
					self.stop()
					continue

			with self.send_lock:
				self.process_result_queue()

			sleep(1)
	def authorize(self):
		return True
	def asyncore_thread(self):
		asyncore.loop(map=self.channel_map)

	def stop(self):
		self.should_stop = True

	def create_input_script(self, psz_timestamp):
  		psz_prefix = ""
  		#use OP_PUSHDATA1 if required
  		if len(psz_timestamp) > 76: psz_prefix = '4c'

  		script_prefix = '04ffff001d0104' + psz_prefix + chr(len(psz_timestamp)).encode('hex')
  		#logging.info(script_prefix + psz_timestamp.encode('hex'))
  		return (script_prefix + psz_timestamp.encode('hex')).decode('hex')


	def create_output_script(self, pubkey):
  		script_len = '41'
  		OP_CHECKSIG = 'ac'
  		return (script_len + pubkey + OP_CHECKSIG).decode('hex')

	def create_transaction(self, input_script, output_script, value):
  		transaction = Struct("transaction", Bytes("version", 4), Byte("num_inputs"), StaticField("prev_output", 32), UBInt32('prev_out_idx'), Byte('input_script_len'), Bytes('input_script', len(input_script)), UBInt32('sequence'), Byte('num_outputs'), Bytes('out_value', 8), Byte('output_script_len'), Bytes('output_script',  0x43), UBInt32('locktime'))
  		tx = transaction.parse('\x00'*(127 + len(input_script)))
  		tx.version           = struct.pack('<I', 1)
  		tx.num_inputs        = 1
  		tx.prev_output       = struct.pack('<qqqq', 0,0,0,0)
  		tx.prev_out_idx      = 0xFFFFFFFF
  		tx.input_script_len  = len(input_script)
  		tx.input_script      = input_script
  		tx.sequence          = 0xFFFFFFFF
  		tx.num_outputs       = 1
  		tx.out_value         = struct.pack('<q' , value)#0x000005f5e100)#012a05f200) #50 coins
  		#tx.out_value         = struct.pack('<q' ,0x000000012a05f200) #50 coins
  		tx.output_script_len = 0x43
  		tx.output_script     = output_script
  		tx.locktime          = 0
  		return transaction.build(tx)
	def create_block_header(self, hash_merkle_root, time, bits, nonce):
  		block_header = Struct("block_header",
    		Bytes("version",4),
    		Bytes("hash_prev_block", 32),
    		Bytes("hash_merkle_root", 32),
    		Bytes("time", 4),
    		Bytes("bits", 4),
    		Bytes("nonce", 4))
  		genesisblock = block_header.parse('\x00'*80)
  		genesisblock.version          = struct.pack('<I', 1)
  		genesisblock.hash_prev_block  = struct.pack('<qqqq', 0,0,0,0)
  		genesisblock.hash_merkle_root = hash_merkle_root
  		genesisblock.time             = struct.pack('<I', time)
  		genesisblock.bits             = struct.pack('<I', bits)
  		genesisblock.nonce            = struct.pack('<I', nonce)
  		return block_header.build(genesisblock)


	def refresh_job(self, j):
		if j == None:
			j = Object()
			j.job_id = '0'
			j.prevhash = '0000000000000000000000000000000000000000000000000000000000000000'
			j.version = '00000001'
			j.nbits = '1d00ffff'
			#j.nbits = '1c028280'
			j.ntime = '495FAB28'
			# j.ntime = '595913da'
			j.extranonce2 = '00000'
			# j.extranonce2 = '000000'
			j.merkle_branch = ''
		j.extranonce2 = self.increment_nonce(j.extranonce2)
		j.ntime = self.increment_nonce(j.ntime)
		print "ntime = " + j.ntime


		self.merkle_root = (hashlib.sha256(hashlib.sha256(self.create_transaction(
			self.create_input_script("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"),
			self.create_output_script(
				"04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"),
			5000000000)).digest()).digest())
		# self.merkle_root = ''.join(list(chunks(self.merkle_root, 2))[::-1])
		merkle_root_reversed = ''
		for word in chunks(self.merkle_root, 4):
			merkle_root_reversed += word[::-1]
		merkle_root = hexlify(merkle_root_reversed)
		self.bits = int(j.nbits, 16)
		self.server_difficulty = (self.bits & 0xffffff) * 2 ** (8 * ((self.bits >> 24) - 3))
		# merkle_root = '3BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A'

		j.block_header = ''.join([j.version, j.prevhash, merkle_root, j.ntime, j.nbits])

		self.jobs[j.job_id] = j
		self.current_job = j

		return j

	def handle_message(self, message):

		#Miner API
		if 'method' in message:

			#mining.notify
			if message['method'] == 'mining.notify':
				params = message['params']

				j = Object()

				j.job_id = params[0]
				j.prevhash = params[1]
				j.coinbase1 = params[2]
				j.coinbase2 = params[3]
				j.merkle_branch = params[4]
				j.version = params[5]
				j.nbits = params[6]
				j.ntime = params[7]
				clear_jobs = params[8]
				if clear_jobs:
					self.jobs.clear()
				j.extranonce2 = self.extranonce2_size * '00'

				j = self.refresh_job(j)

				self.jobs[j.job_id] = j
				self.current_job = j

				self.queue_work(j)


			#mining.set_difficulty
			elif message['method'] == 'mining.set_difficulty':
				say_line("Setting new difficulty: %s", message['params'][0])
				self.server_difficulty = BASE_DIFFICULTY / message['params'][0]

		#responses to server API requests
		elif 'result' in message:

			#response to mining.subscribe
			#store extranonce and extranonce2_size
			if message['id'] == 's':
				self.extranonce = message['result'][1]
				self.extranonce2_size = message['result'][2]
				self.subscribed = True

			#check if this is submit confirmation (message id should be in submits dictionary)
			#cleanup if necessary
			elif message['id'] in self.submits:
				miner, nonce = self.submits[message['id']][:2]
				accepted = message['result']
				self.switch.report(miner, nonce, accepted)
				del self.submits[message['id']]
				if time() - self.last_submits_cleanup > 3600:
					now = time()
					for key, value in self.submits.items():
						if now - value[2] > 3600:
							del self.submits[key]
					self.last_submits_cleanup = now
		return

	def send_message(self, message):
		print message
		self.stop()
		data = dumps(message) + '\n'
		try:
			#self.handler.push(data)

			#there is some bug with asyncore's send mechanism
			#so we send data 'manually'
			#note that this is not thread safe
			if not self.handler:
				return False
			while data:
				sent = self.handler.send(data)
				data = data[sent:]
			return True
		except AttributeError:
			self.stop()
		except Exception:
			say_exception()
			self.stop()

	def increment_nonce(self, nonce):
		next_nonce = long(nonce, 16) + 1
		if len('%x' % next_nonce) > (self.extranonce2_size * 2):
			return '00' * self.extranonce2_size
		return ('%0' + str(self.extranonce2_size * 2) +'x') % next_nonce

	def send_internal(self, result, nonce):
		job_id = result.job_id
		if not job_id in self.jobs:
			return True
		extranonce2 = result.extranonce2
		ntime = pack('<I', long(result.time)).encode('hex')
		hex_nonce = pack('<I', long(nonce)).encode('hex')
		id_ = job_id + hex_nonce
		self.submits[id_] = (result.miner, nonce, time())
		return self.send_message({'params': ["", job_id, extranonce2, long(ntime, 16), long(hex_nonce,16)], 'id': id_, 'method': u'mining.submit'})


	def subscribe(self):
		return True

	def queue_work(self, work, miner=None):
		target = ''.join(list(chunks('%064x' % self.server_difficulty, 2))[::-1])
		self.switch.queue_work(self, work.block_header, target, work.job_id, work.extranonce2, miner)
class Handler:
	def __init__(self, map_, parent):
		self.parent = parent
		self.data = ''

	def handle_close(self):
		self.close()
		self.parent.handler = None

	def handle_error(self):
		say_exception()
		self.parent.stop()

	def collect_incoming_data(self, data):
		self.data += data

	def found_terminator(self):
		message = loads(self.data)
		self.parent.handle_message(message)
		self.data = ''
