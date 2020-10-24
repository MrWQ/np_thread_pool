#!/usr/bin/python3
# -*- coding: utf-8 -*-
import nmap
import datetime
import threadpool
import linecache
import os


log_dir = "log"

def back():
    print('start:', datetime.datetime.now())


def port_scanner(nmap_host, nmap_arg):
    nm = nmap.PortScanner()
    nm.scan(nmap_host, arguments=nmap_arg)
    # print(nm.command_line())
    # print(nm.scaninfo())
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_dic = {"host": host, "port": port, "state": nm[host][proto][port]['state'],
                            "name": nm[host][proto][port]['name']}
                if port_dic:
                    print(port_dic)
                    now = datetime.datetime.now()  # 获取当前时间对象
                    name = now.strftime("%Y-%m-%d")
                    if os.path.exists(log_dir):
                        if os.path.isdir(log_dir):
                            pass
                        else:
                            os.mkdir(log_dir)
                    else:
                        os.mkdir(log_dir)
                    log_file = r'{}/{}.txt'.format(log_dir, name)
                    with open(log_file, 'a', encoding='utf-8') as f:
                        f.write(str(port_dic) + '\n')


def get_arg(ho):
    args_list = []
    for h in ho:
        h = h.strip()
        port_start = 0
        port_end = 512
        port_acc = 512
        port_counter = 128
        for ps in range(port_counter):
            port_start_temp = port_start + ps * port_acc
            port_end_temp = port_end + ps * port_acc
            # print(port_start, port_end, port_start_temp, port_end_temp, port_end_temp - port_start_temp)
            port_range = str(port_start_temp) + '-' + str(port_end_temp)
            argss = '-Pn -n --open --min-hostgroup 4 --min-parallelism 500  -v -p ' + port_range
            # argss = '-Pn -n --min-hostgroup 4 --min-parallelism 500  -v -p ' + port_range
            arg_dic = {}
            arg_dic['nmap_host'] = h
            arg_dic['nmap_arg'] = argss
            tmp = (None, arg_dic)
            args_list.append(tmp)
    return args_list


if __name__ == '__main__':
    ho = linecache.getlines('ip.txt')
    # ho = ['10.172.8.186']
    arg_s = get_arg(ho)
    print(arg_s)
    time_start = datetime.datetime.now()
    pool = threadpool.ThreadPool(48)
    requests = threadpool.makeRequests(port_scanner, arg_s, callback=back())
    [pool.putRequest(req) for req in requests]
    pool.wait()
    time_end = datetime.datetime.now()
    print((time_end - time_start).total_seconds())
