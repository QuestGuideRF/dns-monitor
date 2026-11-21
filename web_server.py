"""
Web Server для мониторинга DNS-запросов
Предоставляет REST API и веб-интерфейс
"""
from flask import Flask ,render_template ,jsonify ,request
from flask_cors import CORS
import sqlite3
from datetime import datetime ,timedelta
from collections import defaultdict
import json
app =Flask (__name__ )
CORS (app )
DB_PATH ='dns_logs.db'
def get_db_connection ():
    """Получение подключения к базе данных"""
    conn =sqlite3 .connect (DB_PATH )
    conn .row_factory =sqlite3 .Row
    return conn
@app .route ('/')
def index ():
    """Главная страница"""
    return render_template ('index.html')
@app .route ('/api/stats')
def get_stats ():
    """Получение общей статистики"""
    conn =get_db_connection ()
    cursor =conn .cursor ()
    cursor .execute ('SELECT COUNT(*) as total FROM dns_queries')
    total =cursor .fetchone ()['total']
    cursor .execute ('SELECT COUNT(*) as blocked FROM dns_queries WHERE blocked = 1')
    blocked =cursor .fetchone ()['blocked']
    cursor .execute ('SELECT COUNT(DISTINCT domain) as unique_domains FROM dns_queries')
    unique_domains =cursor .fetchone ()['unique_domains']
    cursor .execute ('SELECT COUNT(DISTINCT client_ip) as unique_clients FROM dns_queries')
    unique_clients =cursor .fetchone ()['unique_clients']
    cursor .execute ('SELECT AVG(response_time) as avg_time FROM dns_queries WHERE response_time IS NOT NULL')
    avg_time =cursor .fetchone ()['avg_time']or 0
    conn .close ()
    return jsonify ({
    'total_queries':total ,
    'blocked_queries':blocked ,
    'allowed_queries':total -blocked ,
    'unique_domains':unique_domains ,
    'unique_clients':unique_clients ,
    'avg_response_time':round (avg_time *1000 ,2 ),
    'block_rate':round ((blocked /total *100 )if total >0 else 0 ,2 )
    })
@app .route ('/api/recent_queries')
def get_recent_queries ():
    """Получение последних запросов"""
    limit =request .args .get ('limit',100 ,type =int )
    blocked_only =request .args .get ('blocked_only','false').lower ()=='true'
    conn =get_db_connection ()
    cursor =conn .cursor ()
    query ='''        SELECT id, timestamp, domain, client_ip, query_type, response_ip, blocked, response_time
                FROM dns_queries'''
    if blocked_only :
        query +=' WHERE blocked = 1'
    query +=' ORDER BY id DESC LIMIT ?'
    cursor .execute (query ,(limit ,))
    rows =cursor .fetchall ()
    queries =[]
    for row in rows :
        queries .append ({
        'id':row ['id'],
        'timestamp':row ['timestamp'],
        'domain':row ['domain'],
        'client_ip':row ['client_ip'],
        'query_type':row ['query_type'],
        'response_ip':row ['response_ip'],
        'blocked':bool (row ['blocked']),
        'response_time':round (row ['response_time']*1000 ,2 )if row ['response_time']else None
        })
    conn .close ()
    return jsonify (queries )
@app .route ('/api/top_domains')
def get_top_domains ():
    """Получение топ-доменов"""
    limit =request .args .get ('limit',10 ,type =int )
    hours =request .args .get ('hours',24 ,type =int )
    conn =get_db_connection ()
    cursor =conn .cursor ()
    time_threshold =datetime .now ()-timedelta (hours =hours )
    cursor .execute ('''        SELECT domain, COUNT(*) AS count,
                       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS blocked_count
                FROM dns_queries
                WHERE timestamp >= ?
                GROUP BY domain
                ORDER BY count DESC
                LIMIT ?''',(time_threshold ,limit ))
    rows =cursor .fetchall ()
    domains =[]
    for row in rows :
        domains .append ({
        'domain':row ['domain'],
        'count':row ['count'],
        'blocked_count':row ['blocked_count']
        })
    conn .close ()
    return jsonify (domains )
@app .route ('/api/top_clients')
def get_top_clients ():
    """Получение топ-клиентов"""
    limit =request .args .get ('limit',10 ,type =int )
    hours =request .args .get ('hours',24 ,type =int )
    conn =get_db_connection ()
    cursor =conn .cursor ()
    time_threshold =datetime .now ()-timedelta (hours =hours )
    cursor .execute ('''        SELECT client_ip, COUNT(*) AS count,
                       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS blocked_count
                FROM dns_queries
                WHERE timestamp >= ?
                GROUP BY client_ip
                ORDER BY count DESC
                LIMIT ?''',(time_threshold ,limit ))
    rows =cursor .fetchall ()
    clients =[]
    for row in rows :
        clients .append ({
        'client_ip':row ['client_ip'],
        'count':row ['count'],
        'blocked_count':row ['blocked_count']
        })
    conn .close ()
    return jsonify (clients )
@app .route ('/api/timeline')
def get_timeline ():
    """Получение временной статистики"""
    hours =request .args .get ('hours',24 ,type =int )
    interval =request .args .get ('interval','hour')
    conn =get_db_connection ()
    cursor =conn .cursor ()
    time_threshold =datetime .now ()-timedelta (hours =hours )
    if interval =='hour':
        time_format ='%Y-%m-%d %H:00:00'
    else :
        time_format ='%Y-%m-%d %H:%M:00'
    cursor .execute (f'''
        SELECT strftime('{time_format }', timestamp) as time_slot,
               COUNT(*) as total,
               SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
        FROM dns_queries
        WHERE timestamp >= ?
        GROUP BY time_slot
        ORDER BY time_slot
    ''',(time_threshold ,))
    rows =cursor .fetchall ()
    timeline =[]
    for row in rows :
        timeline .append ({
        'time':row ['time_slot'],
        'total':row ['total'],
        'blocked':row ['blocked'],
        'allowed':row ['total']-row ['blocked']
        })
    conn .close ()
    return jsonify (timeline )
@app .route ('/api/search')
def search_queries ():
    """Поиск запросов"""
    domain =request .args .get ('domain','')
    client_ip =request .args .get ('client_ip','')
    blocked =request .args .get ('blocked','')
    limit =request .args .get ('limit',100 ,type =int )
    conn =get_db_connection ()
    cursor =conn .cursor ()
    conditions =[]
    params =[]
    if domain :
        conditions .append ('domain LIKE ?')
        params .append (f'%{domain }%')
    if client_ip :
        conditions .append ('client_ip = ?')
        params .append (client_ip )
    if blocked :
        conditions .append ('blocked = ?')
        params .append (1 if blocked .lower ()=='true'else 0 )
    query ='''        SELECT id, timestamp, domain, client_ip, query_type, response_ip, blocked, response_time
                FROM dns_queries'''
    if conditions :
        query +=' WHERE '+' AND '.join (conditions )
    query +=' ORDER BY id DESC LIMIT ?'
    params .append (limit )
    cursor .execute (query ,params )
    rows =cursor .fetchall ()
    queries =[]
    for row in rows :
        queries .append ({
        'id':row ['id'],
        'timestamp':row ['timestamp'],
        'domain':row ['domain'],
        'client_ip':row ['client_ip'],
        'query_type':row ['query_type'],
        'response_ip':row ['response_ip'],
        'blocked':bool (row ['blocked']),
        'response_time':round (row ['response_time']*1000 ,2 )if row ['response_time']else None
        })
    conn .close ()
    return jsonify (queries )
@app .route ('/api/blocked_domains')
def get_blocked_domains ():
    """Получение списка заблокированных доменов"""
    try :
        with open ('blocklist.txt','r',encoding ='utf-8')as f :
            domains =[line .strip ()for line in f if line .strip ()and not line .startswith ('#')]
        return jsonify ({'count':len (domains ),'domains':domains [:100 ]})
    except FileNotFoundError :
        return jsonify ({'count':0 ,'domains':[]})
@app .route ('/api/clear_old_logs',methods =['POST'])
def clear_old_logs ():
    """Очистка старых логов"""
    days =request .json .get ('days',7 )
    conn =get_db_connection ()
    cursor =conn .cursor ()
    time_threshold =datetime .now ()-timedelta (days =days )
    cursor .execute ('DELETE FROM dns_queries WHERE timestamp < ?',(time_threshold ,))
    deleted =cursor .rowcount
    conn .commit ()
    conn .close ()
    return jsonify ({'success':True ,'deleted':deleted })
if __name__ =='__main__':
    print ("[OK] Web-server zapushen na http://localhost:5000")
    app .run (host ='0.0.0.0',port =5000 ,debug =False )