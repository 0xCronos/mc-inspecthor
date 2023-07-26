import re
import numpy as np
import docker


def read_allowed_players(filepath):
    raw_players = np.loadtxt(filepath, delimiter=':', skiprows=1, dtype=str)
    return raw_players


def create_allowed_players(filepath):
    players = {}
    raw_players = read_allowed_players(filepath)
    for rp in raw_players:
        players[rp[0].lower()] = rp[1]
    return players

def create_player_from_log(raw_data):
    regex = '(.*)\[\/(.*):.*]'
    results = re.search(regex, raw_data)
    player = {'name': results.group(1).lower(), 'ip': results.group(2)}
    return player


def get_logged_in_player(log):
    regex = r'\[Server thread/INFO\]: (.*) logged in'
    if results := re.search(regex, log):
        raw_player = results.group(1)
        return create_player_from_log(raw_player)
    return None


def validate_player_is_allowed(allowed_players, player):
    if player['name'] in allowed_players.keys():
        allowed_ip = allowed_players[player['name']]
        if player['ip'] == allowed_ip:
            return True
        return False
    return False


def ban_player_by_ip(container, ip_address):
    container.exec_run(cmd=f'rcon-cli ban-ip {ip_address}', detach=True)


def start_inspector(allowed_players, container_name):
    client = docker.from_env()
    sv_container = client.containers.get(container_name)
    output_logs = sv_container.attach(stdout=True, stream=True, logs=False)
    for log in output_logs:
        log = log.decode('utf-8')
        if player := get_logged_in_player(log):
            if validate_player_is_allowed(allowed_players, player):
                print(player)
            else:
                print("USUARIO ILEGAL")
                ban_player_by_ip(sv_container, player['ip'])


allowed_players = create_allowed_players('iplist.txt')
start_inspector(allowed_players, 'sv-survival')
