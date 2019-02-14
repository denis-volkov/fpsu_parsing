# -*- coding: utf-8 -*-

import os
import re
import datetime

try:
    from fpsu_private_data import const_ip_ca
except ModuleNotFoundError:
    print('WARNING!!! Скрипт работает без актуальных данных! Not found file "fpsu_private_data.py"')
    const_ip_ca = r'192.168.000.' # Регулярка для адреса ЦА

const_serial = 'Серийный номер ФПСУ'
const_re_ip = r'(\d{3}\.){3}\d{3}' # Регулярка для любого ip-адреса

read_directory = os.walk(os.getcwd())  # Текущая директория скрипта
fpsu_list = []

number_file = 0     # Количество файлов
number_file_sbt = 0  # Количество файлов SBT

print('Привет, человек! Я помогу тебе  :)')
print('Анализ файлов...')

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
                    'abonents': [],
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
                port = 'port1' # Номер порта ФПСУ для записи данных
                fpsu_on_port_temp = {'ip': '', 'crypt': [], 'router': [], 'abonent': []}

                for line in f_sbt:
                    line = line.strip()

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
                    if re.search('порт', line, re.I):
                        flag_port = True
                        flag_fpsu = False
                        flag_router = False
                        flag_abonent = False
                        if re.search(r'порт ?2', line, re.I): # Определяем номер порта
                           port = 'port2'
                        continue
                    if flag_port:
                        line = line.split()
                        if not fpsu[port]['ip']: # Извлекаем адрес порта
                            fpsu[port]['ip'].append(line[0])
                            fpsu[port]['ip'].append(line[1])
                            continue
                        if 'ФПСУ-IP' in line:
                            flag_fpsu = True
                            flag_abonent = False
                            flag_router = False
                            continue
                        if 'МАРШРУТИЗАТОРЫ' in line:
                            flag_router = True
                            flag_fpsu = False
                            flag_abonent = False
                            continue
                        if 'АБОНЕНТЫ' in line:
                            flag_abonent = True
                            flag_router = False
                            flag_fpsu = False
                        if flag_fpsu:
                            if line == []:
                                fpsu[port]['fpsu_on_port'].append(fpsu_on_port_temp)
                                fpsu_on_port_temp = {'ip': '', 'crypt': [], 'router': [], 'abonent': []}
                                flag_forward = False
                                continue
                            if flag_forward:
                                continue
                            if 'Адрес' in line: # Извлекаем адрес ФПСУ за портом
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
                        ###


# <<<<<<<<<<<<<<<12

                    # # Поиск ip адреса ФПСУ ЦА
                    # if line and line in const_start:
                    #     flag_fpsu_block = True
                    #     continue
                    # elif line == const_stop:
                    #     flag_fpsu_block = False
                    #     flag_fpsu_ca = False
                    #     continue
                    # elif line == const_abonent:
                    #     flag_fpsu_abonent = True
                    #     flag_fpsu_block = False
                    #     flag_fpsu_ca = False
                    #     continue
                    # elif 'ПОРТ ' in line:
                    #     flag_fpsu_abonent = False
                    #     continue

                    # if flag_fpsu_block and 'Адрес ' in line:
                    #     try:
                    #         reg = str(re.search(const_ip_ca, line)[0])
                    #     except TypeError:
                    #         pass
                    #     else:
                    #         if 'Адрес ' + reg in line:
                    #             fpsu['ip'].append(reg)
                    #             fpsu['abonents'].append('') # Чтобы не было проблем с индексом
                    #             flag_fpsu_ca = True

                    # if flag_fpsu_ca:
                    #     if not line:
                    #         flag_fpsu_ca = False
                    #     elif 'Криптосеть:' in line:
                    #         fpsu['crypt'].append(line.split()[1])
                    #         fpsu['num_key'].append(line.split()[3])
                    #         fpsu['change_key'].append(line.split()[-2])

                    # if flag_fpsu_abonent:
                    #     if 'Адрес' in line:
                    #         temp_abonent = line.split()[1]
                    #         if 'Host' in line:
                    #             temp_mask = '255.255.255.255'
                    #         else:
                    #             temp_mask = line.split()[-1]
                    #         continue
                    #     if not line:
                    #         temp_mask = ''
                    #         temp_abonent = ''
                    #         flag_fpsu_in_next_line = False
                    #         continue
                    #     if 'Режим работы' in line:
                    #         if line.split()[-1] == "Ретрансляция":
                    #             temp_mask = ''
                    #             temp_abonent = ''
                    #             temp_fpsu = ''
                    #             continue
                    #         elif line.split()[-1] != 'ФПСУ-IP':
                    #             temp_fpsu = line.split()[-1]
                    #         else:
                    #             flag_fpsu_in_next_line = True
                    #             continue

                    #     if flag_fpsu_in_next_line or temp_fpsu:
                    #         if not temp_fpsu:
                    #             temp_fpsu = line.split()[0]
                    #         if temp_fpsu in fpsu['ip']:
                    #             num_fpsu_ca = fpsu['ip'].index(temp_fpsu)
                    #             fpsu['abonents'][num_fpsu_ca] += temp_abonent + ' mask ' + temp_mask + ';'
                    #         flag_fpsu_in_next_line = False
                    #         temp_fpsu = ''

                    #         continue

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
            for i in range(len(fpsu_list)):
                if fpsu_list[i].get('sn') == temp_sn:
                    fpsu_list[i]['name'] = temp_name
                    fpsu_list[i]['active'] = temp_active
                    fpsu_list[i]['reserve'] = temp_reserve
                    break
            temp_sn = ''
            temp_name = ''
            temp_active = ''
            temp_reserve = 0


# Финальный txt
# with open('parsing_conf_fpsu_result.txt', 'w') as f_result:
#     f_result.write('Дата и время анализа: ' + str(datetime.datetime.now()) + '\n')
#     f_result.write('Из ' + str(number_file) + ' файлов, обнаружено ' + str(number_file_sbt) + ' файлов *.SBT\n')

#     f_result.write('\n' + '=' * 30 + '\nФПСУ без туннелей ЦА:\n' + '=' * 30 + '\n')
#     for i in range(len(fpsu_list)):
#         if not fpsu_list[i].get('ip') and fpsu_list[i].get('active'):
#             f_result.write(fpsu_list[i].get('sn') + ' - ' + fpsu_list[i].get('name') + ',\n')

#     f_result.write('\n' + '=' * 30 + '\nНе используется туннель ЦА:\n' + '=' * 30 + '\n')
#     for i in range(len(fpsu_list)):
#         if fpsu_list[i].get('ip') and fpsu_list[i].get('active'):
#             for ii in range(len(fpsu_list[i].get('abonents'))):
#                 if not fpsu_list[i].get('abonents')[ii]:
#                     f_result.write(fpsu_list[i].get('sn') + ' - ' + fpsu_list[i].get('name') + ',\n')
#                 break

#     f_result.write('\n' + '=' * 30 + '\nНекорректное время смены ключа:\n' + '=' * 30 + '\n')
#     for i in range(len(fpsu_list)):
#         if fpsu_list[i].get('change_key') and fpsu_list[i].get('active'):
#             for ii in range(len(fpsu_list[i].get('change_key'))):
#                 if fpsu_list[i].get('change_key')[ii] != '120':
#                     f_result.write(fpsu_list[i].get('sn') + ' - ' + fpsu_list[i].get('name') + ',\n')
#                     break

#     f_result.write('\n' + '=' * 30 + '\nПроблема с резервом:\n' + '=' * 30 + '\n')
#     for i in range(len(fpsu_list)):
#         if fpsu_list[i].get('reserve') == 2 and fpsu_list[i].get('active'):
#             f_result.write(fpsu_list[i].get('sn') + ' - ' + fpsu_list[i].get('name') + ',\n')

#     f_result.write('\n' + '=' * 30 + '\nФПСУ на старых ключах:\n' + '=' * 30 + '\n')
#     for i in range(len(fpsu_list)):
#         if 'SCS' not in fpsu_list[i].get('crypt') and fpsu_list[i].get('active'):
#             f_result.write(fpsu_list[i].get('sn') + ' - ' + fpsu_list[i].get('name') + ',\n')

print('Готово!')
print(fpsu_list[0])
