# XDP Firewall
## Описание
ПО состоит из трёх программ: BPF-XDP модуля xdp_prog, xb-loader, который выполняет загрузку модуля в ядро и xb-stats, который отображает статистику с количеством заблокированных пакетов.

### xb-loader 
xb-loader выполняет загрузку, отключение и обновление фильтров BPF-программы. Для запуска используются следующие аргументы:
```
 -d, --dev <interface>      указывает интерфейс/устройство для работы
 -h, --help                 отображает справку
 -S, --skb-mode             SKB/generic режим загрузки
 -N, --native-mode          native режим загрузки 
 -F, --force                заменяет существующую программу
 -U, --unload               отключает существущую программу
 -W, --update-filters       обновляет фильтры на основе файла xdp.conf
```

Для загрузки BPF-программы необходимо указать режим загрузки (-S или -N и интерфейс -d), например:
```
./xb-loader -S -d enp0s3
```
Для отключения BPF-программы необходимо указать флаг -U, режим загрузки (-S или -N и интерфейс -d), например:
```
./xb-loader -U -S -d enp0s3
```
Для обновления фильтров флаг -W и интерфейс -d:
```
./xb-loader -W -d enp0s3
```
### xb-stats
xb-stats отображает количество заблокированных на интерфейсе пакетов. Синтаксис:
```
./xb-stats -d <interface>
```

## Конфигурация
Описание фильтров хранится в файле xdp.conf в следующем формате:
```sh
filters = (
    {
        #фильтр 1
        enabled = true, 
        proto = "udp",
        dport = 44934
    },
    {
        #фильтр 2
        enabled = true,
        srcip = "8.8.8.8"
    }
);
```
Фильтрация производится только при полном соответствии параметров пакета одному из фильтров, для их настройки используются следующие параметры:
```sh
enabled             true/false, определяет, включен ли фильтр
srcip               ip адрес источника (формат "1.1.1.1")
dstip               ip адрес назначения (формат "1.1.1.1")
proto               протокол "tcp", "icmp" или "udp"
sport               порт адреса источника 
dport               порт адреса назначения 
# блокировка по диапазонам учитывает их граничные значения 
sip_start, sip_end  начало и конец диапазона IP источника, в котором необходимо блокировать пакеты
dip_start, dip_end  начало и конец диапазона IP назначения, в котором необходимо блокировать пакеты
sport_start, sport_end    начало и конец диапазона портов источник, в котором необходимо блокировать пакеты
dport_start, dport_end    начало и конее диапазона портов назначения, в котором необходимо блокировать пакеты
```
Например:
```
{
    #блокируе любые TCP пакеты
    enabled = true,
    proto = "tcp"
},
{
    #блокирует UDP пакеты с портом назначения 5050
    enabled = true,
    proto = "udp",
    dport = 5050
},
{
    #блокирует TCP пакеты с адресами в указанном диапазоне
    enabled = true,
    proto = "tcp",
    sip_start = "104.21.19.0",
    sip_end = "104.21.19.255"
},
{
    #блокирует все порты с 0 до 79 (включая граничные значения)
    enabled = true,
    proto = "tcp",
    sport_start = 0,
    sport_end = 79
},
{
    #этот фильтр отключен и игнорируется
    enabled = false,
    proto = "udp"
}

```
## Сборка и запуск

Необходимые для компиляции зависимости:
```sh
sudo apt-get install build-essential libconfig-dev llvm clang libelf-dev gcc-multilib libbpf-dev
```

Для сборки
```sh
git clone https://github.com/Unit335/xdp-firewall.git
cd xdp-firewall
make
```

Утилиты и файл конфигурации будут расположены в папке build/
Например, по умолчанию конфигурация блокирует все ICMP пакеты: 
```sh
cd build/
sudo ./xb-loader -S -d enp0s3 
ping 1.1.1.1
```
По итогу выполнянения ping результатом должна быть 100% потеря ответных пакетов.
Количество заблокированных пакетов можно посмотреть с помощью:
```
sudo ./xb-stats -d enp0s3
```

Можно также изменить конфигурационный файл, заменив proto = "icmp" на proto = "tcp" и обновив фильтры:
```sh
sudo ./xb-loader -W -d enp0s3 
echo 1 | netcat example.com 80 #отправка TCP пакета, не вернет ничего
ping 1.1.1.1 #будет работать корректно
```
Для отключения программы:
```sh
sudo ./xb-loader -U -S -d enp0s3
```
