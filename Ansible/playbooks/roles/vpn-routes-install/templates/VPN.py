import os
import sys
import ipcalc
from pymongo import MongoClient
import traceback

class VPN:
    def __init__(self):
        #self.instance = VPS(ip, username, ppassword, pport)
        try:
            url = "mongodb://{{ mongodb_user_name }}:{{ mongodb_user_pass }}@localhost:{{ mongodb_port }}/pritunl"
            #print('Connecting to mongodb://' + puser + ":XXXXXXXX@" + phost + ":" + pport + "/" + pdb)
            self.client = MongoClient(url)
            #self.client = MongoClient("mongodb://" + puser + ":" + ppasswd + "@" + phost + ":" + pport + "/" + pdb)
            self.db = self.client.pritunl
            #self.db = pdb
        except Exception as ex:
            print("ERROR, could not connect to MongoDB : " + str(ex))

    def connect(self):
        #self.instance.connect()
        pass

    def disconnect(self):
        #self.instance.disconnect()
        pass

    def add_subnet(self, ip, cidr):
        strip = ip + '/' + str(cidr)
        print('\t\tTrying to add subnet for : ' + strip)
        addr = ipcalc.IP(strip)
        new_route = str(addr.guess_network())
        #print('\tFOUND Network : ' + new_route + ' from IP ' + ip + '/' + str(cidr))
        try:
            col = self.db.servers
            #print('Trying to db.servers.find_one({"_id":"' + os.getenv('MONGO_SERVER_ID') + '"})')
            server = col.find_one({"name":"Global"})
            #print('Got server :')
            #print(server)
            routes = server['routes']
            #print('Routes :')
            #print(routes)
            exists = False
            for route in routes:
                if route['network'] == new_route:
                    exists = True
            if exists:
                print('\tVPS route already known : ' + new_route)
            else:
                print('\tRoute unknown, adding "' + new_route + '" to Global')
                #print('Press Enter to continue...')
                #input()
                routes.append({ 'network': new_route, 'comment': None, 'metric': None, 'nat': True, 'nat_interface': None, 'nat_netmap': None, 'advertise': False, 'vpc_region': None, 'vpc_id': None, 'net_gateway': False, 'server_link': False })
                #routes.append({ 'network': new_route, 'nat': True })
                res = col.update_one({"name":"Global"}, {"$set": { 'routes': routes }}, upsert=False)
                #print('RES')
                #print(res)
        except Exception as ex:
            print('Exception on VPN server "Global" : ' + str(ex))
            print(traceback.format_exc())
            sys.exit()
        try:
            server = col.find_one({"name":"Team"})
            routes = server['routes']
            exists = False
            for route in routes:
                if route['network'] == new_route:
                    exists = True
            if exists:
                print('\tVPS route already known : ' + new_route)
            else:
                print('\tRoute unknown, adding "' + new_route + ' to Team')
                routes.append({ 'network': new_route, 'comment': None, 'metric': None, 'nat': True, 'nat_interface': None, 'nat_netmap': None, 'advertise': False, 'vpc_region': None, 'vpc_id': None, 'net_gateway': False, 'server_link': False })
                res = col.update_one({"name":"Team"}, {"$set": { 'routes': routes }}, upsert=False)
        except Exception as ex:
            print('Exception on VPN server "Team" : ' + str(ex))
            sys.exit()
