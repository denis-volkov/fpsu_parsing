# fpsu_parsing
Тут ничего интересного нет

FPSU = [{   sn: серийный номер,
            name: имя в УА,
            ip: ip адрес ФПСУ ЦА,
            crypt: криптосеть,
            num_key: номер ключа,
            change_key: время смены ключа,
            abonents: абоненты прописанные за ФПСУ,
            active: True | False,
            reserve: 0 - нет резерва | 1 - есть, ок | 2 - есть, не ок
            }]

Новая структура
FPSU = [{   sn: str - серийный номер,
            name: str - имя в УА,
            +crypt_load: list - загруженные ключи,
            port1={
                ip:[ip, mask],                              адрес порта
                fpsu_port = [{                              ФПСУ описанные за портом
                        ip                                  конкретная ФПСУ
                        crypt: [криптосеть, номер, смена],
                        router: [ip],                       адреса роутеров для ФПСУ
                        abonent: [(ip, mask)]               абоненты за ФПСУ
                }]
                routers: {
                    ip: [ip_abonent, mask_abonent]          ip - роутер 
                }
                abonents_port = [(ip_abonent, mask_abonent)]    абоненты за портом ФПСУ
            }
            port2,
            active: True | False - живой/не живой,
            reserve: 0 - нет резерва | 1 - есть, ок | 2 - есть, не ок
        }]