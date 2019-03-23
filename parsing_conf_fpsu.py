# -*- coding: utf-8 -*-

import os
import re
import datetime

try:
    from fpsu_private_data import const_ip_ca
except ModuleNotFoundError:
    print('WARNING!!! Скрипт работает без актуальных данных! Not found file "fpsu_private_data.py"')
    const_ip_ca = r'192.168.000.' # Регулярка для адреса ЦА

def port_internal(fpsu_dict):
    if len(fpsu_dict['port1']['fpsu_on_port']) <= len(fpsu_dict['port2']['fpsu_on_port']):
        return 'port1'
    else:
        return 'port2'

def port_external(fpsu_dict):
    if len(fpsu_dict['port1']['fpsu_on_port']) >= len(fpsu_dict['port2']['fpsu_on_port']):
        return 'port1'
    else:
        return 'port2'

def convert_abonent_cidr(abonent):
    temp = abonent[1].split('.')
    mask = 0
    for i in temp:
        mask += bin(int(i)).count('1')
    return abonent[0] + '/' + str(mask)


const_serial = 'Серийный номер ФПСУ'
const_re_ip = r'(\d{3}\.){3}\d{3}' # Регулярка для любого ip-адреса
const_new_key = 'SCS' # Признак нового ключа
const_change_key = 120 # Корректное время смены ключа

read_directory = os.walk(os.getcwd())  # Текущая директория скрипта
fpsu_list = []

number_file = 0     # Количество файлов
number_file_sbt = 0  # Количество файлов SBT

print('Привет, человек! Я помогу тебе  :)')
print('Анализ файлов...')

fpsu_ignore = []

for files in read_directory:
    for file in files[2]:
        number_file += 1

        print(str(number_file) + '-й\tфайл анализирую...\r', end = '')

        if file.endswith('.SBT'):
            number_file_sbt += 1
            
            fpsu = {
                    'sn': '',
                    'name': '',
                    'crypt_load': [],
                    'port1': {'ip': [], 'fpsu_on_port': [], 'routers': [], 'abonents_on_port':[]},
                    'port2': {'ip': [], 'fpsu_on_port': [], 'routers': [], 'abonents_on_port':[]},
                    'active': '',
                    'reserve': 0}
            
            with open(files[0] + '\\' + file, 'r') as f_sbt:

                # Флаги
                flag_keys = False # Описание ключей 
                flag_port = False # Раздел Порт
                flag_fpsu = False # Внутри блока ФПСУ
                flag_fpsu_router_in_next_line = False
                flag_router = False # Внутри блока МАРШРУТИЗАТОРЫ
                flag_abonent = False
                flag_forward = False # Необходимость промотки парсинга до пустой строки
                flag_retr = False
                port = 'port1' # Номер порта ФПСУ для записи данных
                fpsu_on_port_temp = {'ip': '', 'crypt': [], 'router': [], 'abonent': []}
                abonent_temp = [] # временный список, будет кортежем

                for line in f_sbt:
                    line = line.strip()

                    # Версия 3, пока игнорируем
                    if 'версия 03' in line:
                        fpsu_ignore.append(file)
                        break

                    # Поиск серийного номера
                    if const_serial in line:
                        fpsu['sn'] = line.split()[-1]
                        continue
                    
                    # Поиск загруженных ключей
                    if line.upper() == 'КЛЮЧИ':
                        flag_keys = True
                        continue
                    if flag_keys:
                        if 'Криптосеть' in line:
                            line = line.split()
                            fpsu['crypt_load'].append(line[1])
                            continue
                        elif 'Разрешены' in line:
                            flag_keys = False
                    
                    # Достигли раздела Порт
                    if re.search(r'^порт', line, re.I):
                        flag_port = True
                        flag_fpsu = False
                        flag_router = False
                        flag_abonent = False
                        if re.search(r'порт ?2', line, re.I): # Определяем номер порта
                           port = 'port2'
                        continue
                    if flag_port:
                        if not fpsu[port]['ip']: # Извлекаем адрес порта
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
                                if re.search(const_re_ip, fpsu_on_port_temp['ip']):
                                    fpsu[port]['fpsu_on_port'].append(fpsu_on_port_temp)
                                fpsu_on_port_temp = {'ip': '', 'crypt': [], 'router': [], 'abonent': []}
                                flag_forward = False
                                continue
                            if flag_forward:
                                continue
                            if 'Адрес' in line: # Извлекаем адрес ФПСУ за портом
                                if re.search(const_re_ip, line[1]):
                                    fpsu_on_port_temp['ip'] = line[1]
                                continue
                            if 'Криптосеть:' in line: # Извлекаем крипто для туннеля
                                fpsu_on_port_temp['crypt'].append(line[1])
                                fpsu_on_port_temp['crypt'].append(line[-2])
                                continue
                            if 'Доступен' in line:
                                flag_fpsu_router_in_next_line = True
                                continue
                            if flag_fpsu_router_in_next_line: # Извлекаем роутеры для туннельной ФПСУ
                                if re.search(const_re_ip, line[0]):
                                    fpsu_on_port_temp['router'].extend(line)
                                    continue
                                else:
                                    flag_fpsu_router_in_next_line = False
                                    flag_forward = True # Ускорени и устранение ошибки, т.к. далее также встречается "Адрес"
                                    continue
                        if flag_router:
                            if 'Основной' in line:
                                fpsu[port]['routers'].append({'ip': line[-1], 'abonent':[]})
                        if flag_abonent:
                            if not line:
                                flag_forward = False
                                if abonent_temp:
                                    fpsu[port]['abonents_on_port'].append(tuple(abonent_temp))
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
                                continue

                            # Абонент за ФПСУ, детектируем и зиписываем в мега структуру
                            if 'работы' in line and 'ФПСУ-IP' in line: 
                                for i in fpsu[port]['fpsu_on_port']:
                                    if i['ip'] == line[-3]:
                                        i['abonent'].append(tuple(abonent_temp))
                                flag_forward = True
                                abonent_temp = []
                                continue
                            
                            if 'работы' in line and 'Ретрансляция' in line:
                                flag_retr = True
                                continue

                            if flag_retr:
                                if not 'Доступен' in line: # Абонент за портом
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
                                        i['abonent'].append(tuple(abonent_temp))
                                flag_fpsu_router_in_next_line = False
                                flag_forward = True
                                abonent_temp = []
                                continue

            if fpsu['sn']: # Для игнорирования версии 3
                fpsu_list.append(fpsu)
print('\n', end = '')
print('Обрабатываю полученные данные...')

# Обогащение данными с УА (fpsuinfo.xml): имя, доступность, резерв
with open('fpsuinfo.xml', 'r') as f_xml:

    temp_sn = ''
    temp_name = ''
    temp_active = ''
    temp_reserve = 0

    for line in f_xml:
        if '<!--' in line:
            continue
        elif '<fpsu id="' in line:
            flag_in_fpsu = True
            s_start = line.find('"') + 1
            s_stop = line.find('"', s_start)
            temp_sn = line[s_start:s_stop]

            s_stop = line.find('active')
            s_start = line.find('"', s_stop) + 1
            s_stop = line.find('"', s_start)
            temp_active = bool(int(line[s_start:s_stop]))

            s_start = line.find('<name>') + len('<name>')
            s_stop = line.find('&')
            temp_name = line[s_start:s_stop]
        elif '<reserve' in line:
            s_stop = line.rfind('"')
            s_start = line.rfind('"', 0, s_stop)
            temp_status = line[s_start+1:s_stop]

            s_stop = line.rfind('"', 0, s_start)
            s_start = line.rfind('"', 0, s_stop)
            temp_slave = line[s_start+1:s_stop]

            if temp_slave == '1':
                if temp_status == '4':
                    temp_reserve = 1
                else:
                    temp_reserve = 2
        elif '</fpsu>' in line: # Закончился блок <fpsu>, записываем и сбрасываем то что насобирали
            for i in fpsu_list:
                if i['sn'] == temp_sn:
                    i['name'] = temp_name
                    i['active'] = temp_active
                    i['reserve'] = temp_reserve
                    break
            temp_sn = ''
            temp_name = ''
            temp_active = ''
            temp_reserve = 0

# Финальный txt
with open('parsing_conf_fpsu_result.txt', 'w') as f_result:
    f_result.write('Дата и время анализа: ' + str(datetime.datetime.now()) + '\n')
    f_result.write('Из ' + str(number_file) + ' файлов, обнаружено ' + str(number_file_sbt) + ' файлов *.SBT\n')
    
    
    for i in fpsu_list:
        f_result.write('ФПСУ ' + i['sn'] + '\n')
        for port in ('port1', 'port2'):
            for ii in i[port]['fpsu_on_port']:
                for iii in ii['abonent']:
                    if re.search(r'^011\.', iii[0]):
                        f_result.write(ii['ip'] + ', ' + convert_abonent_cidr(iii) + '\n')
        f_result.write('\n\n')
    
    
    # f_result.write('\nЯ пока не могу обрабатывать версию 3. Проигнорированы ФПСУ:\n')
    # for i in fpsu_ignore:
    #     f_result.write(i + ' ')

    # f_result.write('\n\n' + '=' * 30 + '\nФПСУ без туннелей ЦА:\n' + '=' * 30 + '\n')
    # for i in fpsu_list:
    #     flag_stop_cycle = False # Вспомогательный флаг для отсановки цикла
    #     for port in ('port1', 'port2'):
    #         if flag_stop_cycle:
    #             break
    #         for ii in i[port]['fpsu_on_port']:
    #             if re.search(const_ip_ca, ii['ip']):
    #                 flag_stop_cycle = True
    #                 break
    #     if not flag_stop_cycle:
    #         f_result.write(i['sn'] + ' - ' + i['name'] + ',\n')
    #         #####
    #         temp_abonent = []
    #         port = port_internal(i)
    #         for ii in i[port]['fpsu_on_port']:
    #             temp_abonent.extend(ii['abonent'])
    #         for ii in i[port]['routers']:
    #             temp_abonent.extend(ii['abonent'])
    #         temp_abonent.extend(i[port]['abonents_on_port'])
    #         for ii in range(len(temp_abonent)):
    #             temp_abonent[ii] = convert_abonent_cidr(temp_abonent[ii])
    #         f_result.write('АБОНЕНТЫ: ')
    #         for ii in temp_abonent:
    #             f_result.write(ii + ', ')
    #         f_result.write('\n\n')
    #         #####

    # f_result.write('\n\n' + '=' * 30 + '\nФПСУ c туннелями ЦА и на старых ключах:\n' + '=' * 30 + '\n')
    # for i in fpsu_list:
    #     for port in ('port1', 'port2'):
    #         for ii in i[port]['fpsu_on_port']:
    #             if re.search(const_ip_ca, ii['ip']):
    #                 if const_new_key not in ii['crypt'][0]:
    #                     f_result.write(i['sn'] + ' - ' + i['name'] + ',\n')

    # f_result.write('\n' + '=' * 30 + '\nНе используется туннель ЦА:\n' + '=' * 30 + '\n')
    # for i in fpsu_list:
    #     flag_stop_cycle = False
    #     for port in ('port1', 'port2'):
    #         if flag_stop_cycle:
    #             break
    #         for ii in i[port]['fpsu_on_port']:
    #             if re.search(const_ip_ca, ii['ip']):
    #                 if not ii['abonent']:
    #                     f_result.write(i['sn'] + ' - ' + i['name'] + ',\n')
    #                     flag_stop_cycle = True
    #                     break

    # f_result.write('\n' + '=' * 30 + '\nНекорректное время смены ключа:\n' + '=' * 30 + '\n')
    # for i in fpsu_list:
    #     flag_record_ok = False # Запись имени анализируемой ФПСУ произведена
    #     for port in ('port1', 'port2'):
    #         for ii in i[port]['fpsu_on_port']:
    #             if ii['crypt'][-1] != const_change_key:
    #                 if flag_record_ok:
    #                     f_result.write(', ' + ii['ip'])
    #                 else:
    #                     f_result.write(i['sn'] + ' - ' + i['name'] + ': (')
    #                     f_result.write(ii['ip'])
    #                     flag_record_ok = True
    #     if flag_record_ok:
    #         f_result.write('),\n')

    # f_result.write('\n' + '=' * 30 + '\nПроблема с резервом:\n' + '=' * 30 + '\n')
    # for i in fpsu_list:
    #     if i['reserve'] == 2 and i['active']:
    #         f_result.write(i['sn'] + ' - ' + i['name']+ ',\n')

    # f_result.write('\n' + '=' * 30 + '\nФПСУ на старых ключах:\n' + '=' * 30 + '\n')
    # for i in fpsu_list:
    #     flag_stop_cycle = False # Вспомогательный флаг для отсановки цикла
    #     for port in ('port1', 'port2'):
    #         if flag_stop_cycle:
    #             break
    #         for ii in i[port]['fpsu_on_port']:
    #             if const_new_key not in ii['crypt'][0]:
    #                 flag_stop_cycle = True
    #                 break
    #     if flag_stop_cycle:
    #         f_result.write(i['sn'] + ' - ' + i['name'] + ',\n')

print('Готово!')