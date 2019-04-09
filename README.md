Для работы скрипта необходимо в той же директории:
- Файл 'fpsu_private_data.py', если не будет, то скрипт не сломается, но данные будут не актуальные;
- Файл 'fpsuinfo.xml';
- Файлы *.SBT (неважно в какой директории и какая вложенность, главное чтобы путь начинался с директории со скриптом);
- Интерпретатор версии 3.

Результат работы скрипта появляется в той же директории в файле 'parsing_conf_fpsu_result.txt'. При повторном запуске файл перезапивывается.
Проходят следующие проверки:
- ФПСУ без туннелей ЦА;
- ФПСУ c туннелями ЦА и на старых ключах;
- Не используется туннель ЦА;
- Некорректное время смены ключа;
- Проблема с резервом;
- ФПСУ на старых ключах.

Ещё не реализовано:
- Анализ версии 3;
- Анализ абонентов ЗС (необходимость не очевидно);
- Реализовать выгрузку в excel.

ARP.PY
Временный файл для функционала по L2. Работает и с версией 3

Cтруктура
fpsu_list = [{
            'sn': str - серийный номер,
            'arp_proxy': True | False - в отличии от Амикона человеческое значение (Включён/Отключён соответственно)
            'name': str - имя в УА,
            'crypt_load': [] - загруженные ключи (только криптосеть),
            'port1'={
                'ip':[ip, mask],                       - адрес порта
                'fpsu_on_port' = [{                    - ФПСУ описанные за портом
                        'ip': str                          - конкретная ФПСУ
                        'crypt': [криптосеть, смена],
                        'router': [ip],                - адреса роутеров для ФПСУ
                        'abonent': [(ip_abonent, mask_abonent)]        - абоненты за ФПСУ
                }]
                'routers':[{'ip':'', 'abonent':[(ip_abonent, mask_abonent)]}]
                'abonents_on_port' = [(ip_abonent, mask_abonent)]    - абоненты за портом ФПСУ
            }
            'port2'={
                'ip':[ip, mask],                       - адрес порта
                'fpsu_on_port' = [{                    - ФПСУ описанные за портом
                        'ip': str                          - конкретная ФПСУ
                        'crypt': [криптосеть, смена],
                        'router': [ip],                - адреса роутеров для ФПСУ
                        'abonent': [(ip_abonent, mask_abonent)]        - абоненты за ФПСУ
                }]
                'routers':[{'ip':'', 'abonent':[(ip_abonent, mask_abonent)]}]
                'abonents_on_port' = [(ip_abonent, mask_abonent)]    - абоненты за портом ФПСУ
            }
            'active': True | False - живой/не живой,
            'reserve': 0 - нет резерва | 1 - есть, ок | 2 - есть, не ок
        }]