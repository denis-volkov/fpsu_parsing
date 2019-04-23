# -*- coding: utf-8 -*-
import re


def parsing_sbt(fpsu, file_config, const):
    # Флаги
    flag_keys = False  # Описание ключей
    flag_port = False  # Раздел Порт
    flag_fpsu = False  # Внутри блока ФПСУ
    flag_fpsu_router_in_next_line = False
    flag_router = False  # Внутри блока МАРШРУТИЗАТОРЫ
    flag_abonent = False
    flag_forward = False  # Необходимость промотки парсинга до пустой строки
    flag_retr = False
    port = 'port1'  # Номер порта ФПСУ для записи данных
    fpsu_on_port_temp = {'ip': '', 'crypt': [], 'router': [], 'abonent': []}
    abonent_temp = []  # временный список, будет кортежем
    with open(file_config, 'r', -1, 'cp1251',) as f_sbt:
        for line in f_sbt:
            line = line.strip()
            
            # Поиск серийного номера
            if const['const_serial'] in line:
                fpsu['sn'] = line.split()[-1]
                continue
            # Поиск состояния режима ARP-Proxy
            if 'Отключить < ARP Proxy >' in line:
                if 'Нет' in line:
                    fpsu['arp_proxy'] = True
                else:
                    fpsu['arp_proxy'] = False
            # Поиск загруженных ключей
            if line.upper() == 'КЛЮЧИ':
                flag_keys = True
                continue
            if flag_keys:
                if 'Криптосеть' in line:
                    line = line.split()
                    fpsu['crypt_load'].append(line[1])
                    continue
                elif 'Разрешены' in line or not line:
                    flag_keys = False
            # Достигли раздела Порт
            if re.search(r'^порт', line, re.I):
                flag_port = True
                flag_fpsu = False
                flag_router = False
                flag_abonent = False
                if re.search(r'порт ?2', line, re.I):  # Определяем номер порта
                   port = 'port2'
                continue
            if flag_port:
                if not fpsu[port]['ip']:  # Извлекаем адрес порта
                    fpsu[port]['ip'].append(line.split()[0])
                    fpsu[port]['ip'].append(line.split()[1])
                    continue
                if re.search(r'^ФПСУ-IP$', line, re.I):
                    flag_fpsu = True
                    flag_abonent = False
                    flag_router = False
                    continue
                if re.search(r'^МАРШРУТИЗАТОРЫ$', line, re.I):
                    flag_router = True
                    flag_fpsu = False
                    flag_abonent = False
                    continue
                if re.search(r'^АБОНЕНТЫ$', line, re.I):
                    flag_abonent = True
                    flag_router = False
                    flag_fpsu = False
                    continue
                # неизвестный раздел
                if re.search(r'^[А-Я]{5,} *[А-Я]*', line) and not flag_forward and not flag_fpsu_router_in_next_line and not 'ОТПРАВИТЕЛЬ' in line:
                    flag_abonent = False
                    flag_router = False
                    flag_fpsu = False
                    continue
                line = line.split()
                if flag_fpsu:
                    if not line:
                        if re.search(const['const_re_ip'], fpsu_on_port_temp['ip']):
                            fpsu[port]['fpsu_on_port'].append(
                                fpsu_on_port_temp)
                        fpsu_on_port_temp = {
                            'ip': '', 'crypt': [], 'router': [], 'abonent': []}
                        flag_forward = False
                        continue
                    if flag_forward:
                        continue
                    if 'Адрес' in line:  # Извлекаем адрес ФПСУ за портом
                        if re.search(const['const_re_ip'], line[1]):
                            fpsu_on_port_temp['ip'] = line[1]
                        continue
                    if 'Криптосеть:' in line:  # Извлекаем крипто для туннеля
                        fpsu_on_port_temp['crypt'].append(line[1])
                        fpsu_on_port_temp['crypt'].append(line[-2])
                        continue
                    if 'Доступен' in line:
                        flag_fpsu_router_in_next_line = True
                        continue
                    if flag_fpsu_router_in_next_line:  # Извлекаем роутеры для туннельной ФПСУ
                        if  re.search(const['const_re_ip'], line[0]):
                            fpsu_on_port_temp['router'].extend(line)
                            continue
                        else:
                            flag_fpsu_router_in_next_line = False
                            flag_forward = True  # Ускорени и устранение ошибки, т.к.   ечается     "Адрес"
                            continue
                if flag_router:
                    if 'Основной' in line:
                        fpsu[port]['routers'].append(
                            {'ip': line[-1], 'abonent': []})
                if flag_abonent:
                    if not line:
                        flag_forward = False
                        if abonent_temp:
                            fpsu[port]['abonents_on_port'].append(
                                tuple(abonent_temp))
                            abonent_temp = []
                        continue
                    if flag_forward:
                        continue
                    # Получаем адрес и маску абонента
                    if 'Адрес' in line:
                        abonent_temp.append(line[1])
                        if 'Host' in line:
                            abonent_temp.append('255.255.255.255')
                        else:
                            abonent_temp.append(line[-1])
                        if abonent_temp[0] == 'Произвольный':
                            abonent_temp = ('0.0.0.0', '0.0.0.0')
                        continue
                    # Абонент за ФПСУ, детектируем и зиписываем в мега структуру
                    if 'работы' in line and 'ФПСУ-IP' in line:
                        for i in fpsu[port]['fpsu_on_port']:
                            if i['ip'] == line[-3]:
                                i['abonent'].append(
                                    tuple(abonent_temp))
                        flag_forward = True
                        abonent_temp = []
                        continue
                    if 'работы' in line and 'Ретрансляция' in line:
                        flag_retr = True
                        continue
                    if flag_retr:
                        if not 'Доступен' in line:  # Абонент за портом
                            flag_retr = False
                            flag_forward = True
                            continue
                        else:
                            # Абонент за маршрутизатором
                            flag_fpsu_router_in_next_line = True
                            flag_retr = False
                            continue
                    if flag_fpsu_router_in_next_line:
                        for i in fpsu[port]['routers']:
                            if i['ip'] == line[0]:
                                i['abonent'].append(
                                    tuple(abonent_temp))
                        flag_fpsu_router_in_next_line = False
                        flag_forward = True
                        abonent_temp = []
                        continue
    return fpsu
