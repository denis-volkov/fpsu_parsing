# -*- coding: utf-8 -*-

import os
import re
import datetime

# try:
#     from fpsu_private_data import const_ip_ca
# except ModuleNotFoundError:
#     print('WARNING!!! Скрипт работает без актуальных данных! Not found file "fpsu_private_data.py"')
#     const_ip_ca = r'192.168.000.' # Регулярка для адреса ЦА

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

print('Привет, органика! Я помогу тебе  :)')
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
                    'arp_proxy': False,
                    'name': '',
                    'port1': '',
                    'port2': ''}
                    

            with open(os.path.join(files[0], file), 'r', -1, 'cp1251',) as f_sbt:
                flag_port1 = False # Раздел Порт
                flag_port2 = False
                for line in f_sbt:
                    line = line.strip()

                    if const_serial in line:
                        fpsu['sn'] = line.split()[-1]
                        continue

                    # Поиск состояния режима ARP-Proxy
                    if 'Отключить < ARP Proxy >' in line:
                        if 'Нет' in line:
                            fpsu['arp_proxy'] = True
                            continue

                    if 'ПОРТ 1' in line:
                        flag_port1 = True
                        continue
                    
                    if flag_port1:
                        fpsu['port1'] = line.split()[0]
                        flag_port1 = False
                        continue

                    if 'ПОРТ 2' in line:
                        flag_port2 = True
                        continue

                    if flag_port2:
                        fpsu['port2'] = line.split()[0]
                        flag_port2 = False
                        continue
                    
                fpsu_list.append(fpsu)
print('\n', end = '')
print('Обрабатываю полученные данные...')

# Обогащение данными с УА (fpsuinfo.xml): имя, доступность, резерв
with open('fpsuinfo.xml', 'r', -1, 'cp1251') as f_xml:

    temp_sn = ''
    temp_name = ''

    for line in f_xml:
        if '<!--' in line:
            continue
        elif '<fpsu id="' in line:
            flag_in_fpsu = True
            s_start = line.find('"') + 1
            s_stop = line.find('"', s_start)
            temp_sn = line[s_start:s_stop]

            # s_stop = line.find('active')
            # s_start = line.find('"', s_stop) + 1
            # s_stop = line.find('"', s_start)
            # temp_active = bool(int(line[s_start:s_stop]))

            s_start = line.find('<name>') + len('<name>')
            s_stop = line.find('&')
            temp_name = line[s_start:s_stop]
        # elif '<reserve' in line:
        #     s_stop = line.rfind('"')
        #     s_start = line.rfind('"', 0, s_stop)
        #     temp_status = line[s_start+1:s_stop]

        #     s_stop = line.rfind('"', 0, s_start)
        #     s_start = line.rfind('"', 0, s_stop)
        #     temp_slave = line[s_start+1:s_stop]

        #     if temp_slave == '1':
        #         if temp_status == '4':
        #             temp_reserve = 1
        #         else:
        #             temp_reserve = 2
        elif '</fpsu>' in line: # Закончился блок <fpsu>, записываем и сбрасываем то что насобирали
            for i in fpsu_list:
                if i['sn'] == temp_sn:
                    i['name'] = temp_name
                    break
            temp_sn = ''
            temp_name = ''


# Финальный txt
with open('parsing_conf_fpsu_result_arp.txt', 'w') as f_result:
    f_result.write('Дата и время анализа: ' + str(datetime.datetime.now()) + '\n')
    f_result.write('Из ' + str(number_file) + ' файлов, обнаружено ' + str(number_file_sbt) + ' файлов *.SBT\n')
    
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

    f_result.write('\n' + '=' * 30 + '\nФПСУ работает в режиме L2 и адреса на портах разные:\n' + '=' * 30 + '\n')
    for i in fpsu_list:
        if i['arp_proxy']:
            if i['port1'] != i['port2']:
                f_result.write(i['sn'] + ' - ' + i['name'] + ' - Port 1 ' +  i['port1'] + ' - Port 2 - ' + i['port2'] + '\n')
    
    f_result.write('\n' + '=' * 30 + '\nФПСУ работает в режиме L2 с адресацией 55*:\n' + '=' * 30 + '\n')
    for i in fpsu_list:
        if i['arp_proxy']:
            if re.search(r'^055.', i['port1']) or re.search(r'^055.', i['port2']):
                f_result.write(i['sn'] + ' - ' + i['name'] + ' - Port 1 ' +  i['port1'] + ' - Port 2 - ' + i['port2'] + '\n')
print('Готово!')