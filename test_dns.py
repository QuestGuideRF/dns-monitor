import socket
import struct
def create_dns_query (domain ):
    transaction_id =0x1234
    flags =0x0100
    questions =1
    answer_rrs =0
    authority_rrs =0
    additional_rrs =0
    header =struct .pack ('!HHHHHH',transaction_id ,flags ,questions ,
    answer_rrs ,authority_rrs ,additional_rrs )
    question =b''
    for part in domain .split ('.'):
        question +=struct .pack ('B',len (part ))+part .encode ()
    question +=b'\x00'
    question +=struct .pack ('!HH',1 ,1 )
    return header +question
def test_dns_server (host ='127.0.0.1',port =5353 ):
    print (f"Тестирование DNS-сервера {host }:{port }")
    print ("-"*50 )
    test_domains =[
    'google.com',
    'youtube.com',
    'facebook.com',
    'doubleclick.net',
    'github.com',
    'stackoverflow.com'
    ]
    sock =socket .socket (socket .AF_INET ,socket .SOCK_DGRAM )
    sock .settimeout (5 )
    for domain in test_domains :
        try :
            query =create_dns_query (domain )
            sock .sendto (query ,(host ,port ))
            response ,_ =sock .recvfrom (512 )
            position =len (create_dns_query (domain ))
            if response [position ]&0xC0 ==0xC0 :
                position +=2
            else :
                while response [position ]!=0 :
                    position +=1
                position +=1
            position +=8
            data_length =struct .unpack ('!H',response [position :position +2 ])[0 ]
            position +=2
            if data_length ==4 :
                ip_bytes =response [position :position +4 ]
                ip ='.'.join (str (b )for b in ip_bytes )
                if ip =='0.0.0.0':
                    print (f"[BLOCKED] {domain :30} -> ZABLOKIROWAN")
                else :
                    print (f"[OK] {domain :30} -> {ip }")
            else :
                print (f"[OK] {domain :30} -> Response received")
        except socket .timeout :
            print (f"[TIMEOUT] {domain :30} -> TIMEOUT")
        except Exception as e :
            print (f"[ERROR] {domain :30} -> ERROR: {e }")
    sock .close ()
    print ("-"*50 )
    print ("Тестирование завершено!")
if __name__ =='__main__':
    import sys
    host =sys .argv [1 ]if len (sys .argv )>1 else '127.0.0.1'
    port =int (sys .argv [2 ])if len (sys .argv )>2 else 5353
    test_dns_server (host ,port )