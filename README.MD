![Peek 2023-02-08 06-13](https://user-images.githubusercontent.com/62081392/217420080-1e4ae7ca-83b4-4d11-94cf-511904ca4d20.gif)
<h1>Это демон, обеспечивающий общение между UDP сокетом и виртуальным COM портом</h1>

<h2>Как запустить:</h2>
<code>gcc -Wall -g driver.c -o driver
./driver [port]</code>

[port] - порт, на котором будет висеть UDP сокет.

Программа откроет в на localhost:port сокет, а в директории проекта создаст два виртуальных COM порта: для клиента и для сервера. ttyS0 - устройство демона. Подключиться к устройству клиента можно так:

<code>minicom -D /full/path/to/project/ttyS1 </code>

Подключиться к сокету можно, например, с помощью netcat:

<code>nc -u localhost 1488</code>


<h2>Что не получилось</h2>

Из недочетов моей реализации можно выделить 2 важные вещи:

1. Первые символы должен начать передавать сокет в COM порт. Если COM порт начнет передавать данные первым, демону будет просто некуда их отсылать (поля struct sockaddr можно узнать только после первого успешного системного вызова rcvfrom(), а без этой структуры sendto() не будет иметь адресата). Насколько я понял, poll() не умеет пробуждаться от подключения нового клиента к сокету. Это точно умеет делать select(), но при использовании этого вызова начинаются другие
сложности. Как это недоразумение решить - мне пока не понятно.

2. У меня так и не получилось заставить клиент сокета работать в неблокирующем режиме и без эхо. По идее этого можно добиться через tssetattr(), но именно у ф.д. сокета при вызове tssetattr() с любым (!) сожержимым struct termios вылетает ошибка "Inappropriate ioctl for device". Причину этой ошибки а также возможные варианты ее устранения мне установить не удалось:(

