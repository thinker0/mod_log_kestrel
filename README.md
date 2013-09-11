mod_log_kestrel
===============

httpd.conf
=============
```
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
```
```
    #CustomLog "logs/access_log" combined
    <IfModule log_kestrel_module>
        CustomLog |kestrel://queue_name@localhost:22133 combined
    </IfModule>
```
