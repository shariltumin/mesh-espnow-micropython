
from machine import reset
# from hashlib import sha1 as sha
from sys import platform
import time
import urandom
from espnow_init import MAC, NID, BAS, ew, encrypt, decrypt
from worker import task, MT

urandom.seed(4)

# global structure
MESH = []    # authenticated mac address of current mesh-network
MID = [b'0'*11]*100 # # message id array for already processed messages
midp = 0     # the index to insert new MID. MID[midp]=msg_id; midp=(midp+1)%100

@task
def process(pm): # process payload
    peer, payload = pm
    s=(yield)
    msg = decrypt(peer)(payload) # pl=encrypt(mac)(msg)
    print(MAC.hex(), peer.hex(), msg)
    yield 'OK'

@task
def forward(pm): # message forwarding
    sender, source, msg = pm
    s=(yield)
    for peer in MESH:
       if peer not in (sender, source):
          try:
             w=ew.get_peer(peer)     # this will fail if peer not registered
             ok = ew.send(peer, msg) # forward the message
             if not ok:
                print('Fail to forward msg to', peer.hex())
                MESH.remove(peer) # peer may be down or out of reach
          except:
             print('Peer', peer.hex(), 'not found (forward)')
       yield # one at a time
    yield 'OK'

@task
def get_bye(pm):
    peer = pm[0]
    s=(yield)
    try:
       MESH.remove(peer)
    except:
       pass
    try:
       ew.del_peer(peer)
    except:
       pass
    yield 'OK'

@task 
def send_auq(pm): # send AUQ in response to HEY
    peer = pm[0]
    s=(yield)
    payload = encrypt(MAC)(peer)
    msg = b'AUQ'+payload
    try:
       w=ew.get_peer(peer)
       ok = ew.send(peer, msg)
       if not ok:
          print('Fail to send AUQ to', peer.hex())
    except:
       print('Peer', peer.hex(), 'not found (send_auq)')
    yield 'OK'

@task
def send_aur(pm): # process AUQ and send back AUR
    sender, msg = pm
    s=(yield)
    if len(msg)<9: yield 'ER' 
    node = decrypt(sender)(msg[3:])
    if node != MAC:
       print('Fail to authenticate', sender.hex(), 'from AUQ message')
    else:
       if sender not in MESH: # we can choose to include node in MESH or not
          MESH.append(sender) # node is now authenticated
       payload = encrypt(MAC)(sender)
       msg = b'AUR'+payload
       try:
          w=ew.get_peer(sender)
          ok = ew.send(sender, msg)
          if not ok:
             print('Fail to send AUR to', sender.hex())
       except:
          print('Peer', sender.hex(), 'not found (send_aur)')
    yield 'OK'

@task
def get_aur(pm): # process AUR 
    sender, msg = pm
    s=(yield)
    if len(msg)<9: yield 'ER' 
    node = decrypt(sender)(msg[3:])
    if node != MAC:
       print('Fail to authenticate', sender.hex(), 'from AUR message')
    else:
       if sender not in MESH: # we can choose to include node in MESH or not
          MESH.append(sender) # node is now authenticated
    yield 'OK'

@task
def send_msg(pm): # send a message 'MSG' to all authenticated peers
    payload = pm[0]
    s=(yield)
    if type(payload)!=bytes:
       payload=b'%s'%payload
    # msg='MSGyyyyyyxxxxxxiiiiiddddd........'
    # target=msg[3:3+6]   # yyyyyy 
    # source=msg[3+6:3+6+6] # xxxxxx       
    # mid=msg[3+6:3+6+6+5]  # xxxxxxiiiii  message id
    target=BAS  # sent to all
    mid=b'%s%05d'%(MAC, hash('%d'%time.ticks_us())) # 11 bytes message ID
    msg=b'MSG'+target+mid+encrypt(MAC)(payload)
    for peer in MESH: # send to all authenticated peer
       try:
          w=ew.get_peer(peer)
          ok = ew.send(peer, msg) # forward the message
          if not ok:
             print('Fail to send MSG to', peer.hex())
             MESH.remove(peer) # peer may be down or out of reach
          yield # one at a time
       except:
          print('Peer', peer.hex(), 'not found (send_msg)')
          print(ew.peers_table)
    yield 'OK'

@task
def get_any(pm): # get any package from espnow inbuffer
    global MID, midp
    s=(yield)
    while 1:
       if not ew.any(): 
          # print('get_any got', ew.any())
          wait=s.delay(1*1000)     # 1 sec.
          while wait():yield
          continue  # restart loop
       peer, msg = ew.recv() # this is blocking, therefore after ew.any()
       if len(msg) < 3: # msg MUST be 3 chars or more
          yield         # yield to other tasks
          continue      # before continue loop
       # add peer to espnow peers_table
       try:
          ew.add_peer(peer)
       except:
          pass
       msg_typ = msg[:3]     # message type: HEY, AUQ, AUR, MSG, BYE
       if msg_typ == b'HEY':
          print('Get HEY from', peer.hex())
          # send AUQ to peer regardless MESH membership
          mt.worker(send_auq, (peer,))
          yield
       elif msg_typ == b'AUQ':
          print('Get AUQ from', peer.hex())
          # process AUQ and send AUR to peer 
          mt.worker(send_aur, (peer, msg))
          yield
       elif msg_typ == b'AUR':
          print('Get AUR from', peer.hex())
          # process AUR from peer 
          mt.worker(get_aur, (peer, msg))
          yield
       elif msg_typ == b'MSG':
          print('Get MSG from', peer.hex(), 'message', msg[:20], '...')
          # mid=b'%s%05d'%(MAC, hash('%d'%time.ticks_us()))
          # msg='MSGyyyyyyxxxxxxiiiiiddddd........'
          # target=msg[3:3+6]   # yyyyyy 
          # source=msg[3+6:3+6+6] # xxxxxx       
          # mid=msg[3+6:3+6+6+5]  # xxxxxxiiiii  message id
          # payload=msg[3+6+6+5:]
          if peer in MESH:   # authenticated peer?
             if len(msg)<20: continue
             msg_id = msg[9:20] # message id: 11 bytes 
             if msg_id not in MID:
                MID[midp]=msg_id; midp=(midp+1)%100
                target=msg[3:9]
                source=msg[9:15]
                payload = msg[20:] # payload: rest of bytes at pos 20 onward
                if len(payload)==0: continue
                # process payload - task
                mt.worker(process, (source, payload))
                if MAC==target:  # distination reach
                   print('Distination',  target.hex(), 'reached')
                else:
                   # forward msg to know peers but not to peer it came from 
                   mt.worker(forward, (peer, source, msg))
          yield
       elif msg_typ == b'BYE':
          print('Get BYE from', peer.hex())
          # remove peer from MESH membership and espnow peers list
          mt.worker(get_bye, (peer,))
          yield
       else:
          print("Unknown message type", msg_typ, "from", peer.hex())
          yield

@task
def mesh_in(pm): # try to join mesh network
    val = pm[0]  # at regular interval in millisecond
    s=(yield)
    if len(MESH) == 0:  # do it immedeatly if no peers
       print(MAC.hex(), 'sending HEY')
       ok = ew.send(BAS, b'HEY') # broadcast the 'HEY' message
       wait=s.delay(30*1000)     # wait 30 secs.
       while wait():yield
    else:
       wait=s.delay(val)
       while wait():yield
       print(MAC.hex(), 'sending HEY')
       ok = ew.send(BAS, b'HEY')
       wait=s.delay(30*1000)     # wait 30 secs.
       while wait():yield
    mt.worker(mesh_in, (val, )) # every val milliseconds
    yield 'OK'

@task
def debug(pm): # print error log if any
    val = pm[0]
    s=(yield)
    while 1:
       err = mt.log()
       if err:
          print('*DEBUG*', err)
       wait=s.delay(val)     # wait val secs.
       while wait():yield

@task 
def test(pm): # simulate send MSG at random interval
    s=(yield)
    wait=s.delay((urandom.getrandbits(3)+10)*1000)
    while wait():yield
    if len(MESH) > 0:  # there are some peers to send MSG to
        msg = b'The time at ' + NID + ' is now ' + b'%d:%d:%d'%time.localtime()[3:6]      
        print(MAC.hex(), 'sending MSG')
        print(MESH)
        mt.worker(send_msg, (msg, ))
    mt.worker(test, ()) # try again
    yield 'OK'


print('MAC:', MAC)

mt=MT(20) # max 20 tasks

# register initial tasks
mt.worker(debug, (30*1000, ))  # print error (if any) every 30 sec.
mt.worker(mesh_in, (5*60*1000, )) # every 5 mins
mt.worker(get_any, ()) 
mt.worker(test, ()) 

print('Start MESH simulation')

# start MESH simulation
mt.start()

# Will never reach here
print('Program aborted due to error', mt.log())

