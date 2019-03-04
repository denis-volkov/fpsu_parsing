Новая структура
fpsu_list = [{
            'sn': str - серийный номер,
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