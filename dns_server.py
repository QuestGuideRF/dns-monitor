import socket
import struct
import threading
import time
from datetime import datetime
import sqlite3
from collections import defaultdict
import json
class DNSServer :
    def __init__ (self ,host ='0.0.0.0',port =53 ,upstream_dns ='8.8.8.8',db_path ='dns_logs.db'):
        self .host =host
        self .port =port
        self .upstream_dns =upstream_dns
        self .db_path =db_path
        self .sock =None
        self .running =False
        self .stats =defaultdict (int )
        self .blocked_domains =set ()
        self .init_db ()
        self .load_blocklist ()
    def init_db (self ):
        conn =sqlite3 .connect (self .db_path )
        cursor =conn .cursor ()
        cursor .execute ('''            CREATE TABLE IF NOT EXISTS dns_queries (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                            domain TEXT NOT NULL,
                            client_ip TEXT,
                            query_type TEXT,
                            response_ip TEXT,
                            blocked INTEGER DEFAULT 0,
                            response_time REAL
                        )''')
        cursor .execute ('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_queries(timestamp)
        ''')
        cursor .execute ('''
            CREATE INDEX IF NOT EXISTS idx_domain ON dns_queries(domain)
        ''')
        cursor .execute ('''
            CREATE INDEX IF NOT EXISTS idx_blocked ON dns_queries(blocked)
        ''')
        conn .commit ()
        conn .close ()
    def load_blocklist (self ):
        try :
            with open ('blocklist.txt','r',encoding ='utf-8')as f :
                self .blocked_domains =set (line .strip ().lower ()for line in f if line .strip ()and not line .startswith ('#'))
            print (f"[OK] Zagruzheno {len (self .blocked_domains )} domenov dlya blokirovki")
        except FileNotFoundError :
            print ("[!] Fail blocklist.txt ne naiden, blokirovka otklyuchena")
            self .blocked_domains =set ()
    def is_blocked (self ,domain ):
        domain =domain .lower ().rstrip ('.')
        if domain in self .blocked_domains :
            return True
        parts =domain .split ('.')
        for i in range (len (parts )):
            subdomain ='.'.join (parts [i :])
            if subdomain in self .blocked_domains :
                return True
        return False
    def log_query (self ,domain ,client_ip ,query_type ,response_ip ,blocked ,response_time ):
        try :
            conn =sqlite3 .connect (self .db_path )
            cursor =conn .cursor ()
            cursor .execute ('''                INSERT INTO dns_queries (domain, client_ip, query_type, response_ip, blocked, response_time)
                                VALUES (?, ?, ?, ?, ?, ?)''',(domain ,client_ip ,query_type ,response_ip ,blocked ,response_time ))
            conn .commit ()
            conn .close ()
        except Exception as e :
            print (f"[!] Ошибка логирования: {e }")
    def parse_dns_query (self ,data ):
        try :
            transaction_id =struct .unpack ('!H',data [0 :2 ])[0 ]
            position =12
            domain_parts =[]
            while True :
                length =data [position ]
                if length ==0 :
                    break
                position +=1
                domain_parts .append (data [position :position +length ].decode ('utf-8',errors ='ignore'))
                position +=length
            domain ='.'.join (domain_parts )
            position +=1
            query_type =struct .unpack ('!H',data [position :position +2 ])[0 ]
            query_class =struct .unpack ('!H',data [position +2 :position +4 ])[0 ]
            return transaction_id ,domain ,query_type ,query_class
        except Exception as e :
            print (f"[!] Ошибка парсинга DNS: {e }")
            return None ,None ,None ,None
    def create_blocked_response (self ,transaction_id ,query_data ):
        try :
            flags =0x8180
            questions =1
            answers =1
            authority =0
            additional =0
            header =struct .pack ('!HHHHHH',transaction_id ,flags ,questions ,answers ,authority ,additional )
            position =12
            while query_data [position ]!=0 :
                position +=1
            position +=5
            question =query_data [12 :position ]
            answer =(
            b'\xc0\x0c'
            b'\x00\x01'
            b'\x00\x01'
            b'\x00\x00\x00\x3c'
            b'\x00\x04'
            b'\x00\x00\x00\x00'
            )
            return header +question +answer
        except Exception as e :
            print (f"[!] Ошибка создания блокированного ответа: {e }")
            return None
    def forward_dns_query (self ,query_data ):
        try :
            sock =socket .socket (socket .AF_INET ,socket .SOCK_DGRAM )
            sock .settimeout (5 )
            sock .sendto (query_data ,(self .upstream_dns ,53 ))
            response ,_ =sock .recvfrom (512 )
            sock .close ()
            return response
        except Exception as e :
            print (f"[!] Ошибка пересылки DNS: {e }")
            return None
    def extract_ip_from_response (self ,response_data ):
        try :
            position =12
            while response_data [position ]!=0 :
                position +=1
            position +=5
            if response_data [position ]&0xC0 ==0xC0 :
                position +=2
            else :
                while response_data [position ]!=0 :
                    position +=1
                position +=1
            position +=8
            data_length =struct .unpack ('!H',response_data [position :position +2 ])[0 ]
            position +=2
            if data_length ==4 :
                ip_bytes =response_data [position :position +4 ]
                ip ='.'.join (str (b )for b in ip_bytes )
                return ip
        except :
            pass
        return None
    def handle_request (self ,data ,addr ):
        start_time =time .time ()
        transaction_id ,domain ,query_type ,query_class =self .parse_dns_query (data )
        if not domain :
            return
        client_ip =addr [0 ]
        query_type_str ='A'if query_type ==1 else 'AAAA'if query_type ==28 else f'TYPE{query_type }'
        if self .is_blocked (domain ):
            print (f"[BLOCKED] {domain } ot {client_ip }")
            response =self .create_blocked_response (transaction_id ,data )
            if response :
                self .sock .sendto (response ,addr )
            response_time =time .time ()-start_time
            self .log_query (domain ,client_ip ,query_type_str ,'0.0.0.0',1 ,response_time )
            self .stats ['blocked']+=1
        else :
            response =self .forward_dns_query (data )
            if response :
                self .sock .sendto (response ,addr )
                response_ip =self .extract_ip_from_response (response )
                response_time =time .time ()-start_time
                print (f"[OK] {domain } -> {response_ip or 'N/A'} ot {client_ip } ({response_time *1000 :.1f}ms)")
                self .log_query (domain ,client_ip ,query_type_str ,response_ip ,0 ,response_time )
                self .stats ['allowed']+=1
            else :
                response_time =time .time ()-start_time
                self .log_query (domain ,client_ip ,query_type_str ,None ,0 ,response_time )
    def start (self ):
        try :
            self .sock =socket .socket (socket .AF_INET ,socket .SOCK_DGRAM )
            self .sock .setsockopt (socket .SOL_SOCKET ,socket .SO_REUSEADDR ,1 )
            self .sock .bind ((self .host ,self .port ))
            self .running =True
            print (f"[OK] DNS-server zapushen na {self .host }:{self .port }")
            print (f"[OK] Upstream DNS: {self .upstream_dns }")
            print (f"[OK] Baza dannykh: {self .db_path }")
            print ("-"*60 )
            while self .running :
                try :
                    data ,addr =self .sock .recvfrom (512 )
                    thread =threading .Thread (target =self .handle_request ,args =(data ,addr ))
                    thread .daemon =True
                    thread .start ()
                except Exception as e :
                    if self .running :
                        print (f"[!] Ошибка обработки запроса: {e }")
        except PermissionError :
            print ("[!] ERROR: Trebuyutsya prava administratora dlya porta 53")
            print ("[!] Zapustite skript s pravami administratora ili ispolzuite drugoi port")
        except Exception as e :
            print (f"[!] Ошибка запуска сервера: {e }")
        finally :
            self .stop ()
    def stop (self ):
        self .running =False
        if self .sock :
            self .sock .close ()
        print ("\n[OK] DNS-server ostanovlen")
        print (f"[OK] Statistika: Razresheno: {self .stats ['allowed']}, Zablokirovano: {self .stats ['blocked']}")
if __name__ =='__main__':
    import sys
    port =5353
    upstream ='8.8.8.8'
    if len (sys .argv )>1 :
        port =int (sys .argv [1 ])
    if len (sys .argv )>2 :
        upstream =sys .argv [2 ]
    server =DNSServer (port =port ,upstream_dns =upstream )
    try :
        server .start ()
    except KeyboardInterrupt :
        print ("\n[!] Получен сигнал остановки...")
        server .stop ()