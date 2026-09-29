# ByeByeDPI

Нативная утилита обхода систем глубокого анализа пакетов (DPI) для Windows на базе драйвера фильтрации сетевого уровня WinDivert.

[![Download Latest Release](https://img.shields.io/badge/Download-Latest_Release-2ea44f?style=for-the-badge&logo=github)](https://github.com/Jwachka1337/ByeByeDPI/releases/tag/1.0)

## Архитектурные особенности и ключевые механизмы

* **Программный генератор TLS ClientHello:**

  В `packet_engine.cpp` встроен полноценный программный генератор пакетов TLS: он на лету собирает структуры Handshake, вычисляет длины расширений и строит правильный ClientHello под любой указанный домен без внешних дампов.

* **Динамическая генерация поддоменов под размер:**

  В проекте реализован алгоритм, который анализирует длину реального домена (например, длинный URL CDN YouTube `rr3---sn-xxxx.googlevideo.com`) и на лету генерирует синтетический поддомен Google ровно такой же длины, сохраняя целостность структуры TLS.

* **Таргетированный сброс IPv6 (`drop_ipv6_target_ports`):**

  Опция `drop_ipv6_target_ports` на уровне ядра сбрасывает исходящие IPv6-пакеты только на целевые HTTPS/RTC порты. Это заставляет браузеры и Discord мгновенно, без задержек алгоритма Happy Eyeballs, переключаться на IPv4, где гарантированно срабатывает десинхронизация.

* **Мгновенное обновление доменов без перезапуска:**

  Список целевых доменов защищен потокобезопасным мьютексом: добавление или удаление домена через интерфейс применяется рабочими потоками мгновенно без остановки фильтрации.

## Системные требования

* Windows 10 / 11 (x64)

* Права администратора 

* Visual Studio 2022 с установленным компонентом «Разработка классических приложений на C++»

## Инструкция по сборке из исходников

### Шаг 1. Подготовка структуры проекта

Создайте папку проекта (например, `C:\byebyeDPI`) и поместите в нее исходные файлы:

```
C:\byebyeDPI\
├── main.cpp
├── packet_engine.cpp
├── packet_engine.hpp
├── windivert_manager.cpp
├── windivert_manager.hpp
├── windivert_deployer.cpp
├── windivert_deployer.hpp
├── protocol_headers.hpp
├── embedded_payloads.hpp
└── resource_ids.h

```

### Шаг 2. Скачивание WinDivert SDK

1. Загрузите архив `WinDivert-2.2.2-A.zip` с официального сайта: <https://reqrypt.org/windivert.html>.

2. Распакуйте библиотеки и заголовки так, чтобы внутри папки проекта получилась следующая структура:

```
windivert_sdk/
├── include/
│   └── windivert.h
└── bin/
    └── x64/
        ├── WinDivert.dll
        ├── WinDivert64.sys
        └── WinDivert.sys

```

### Шаг 3. Создание файла ресурсов

В корневой папке проекта создайте файл `windivert_resources.rc` со следующим содержимым:

```
#include "resource_ids.h"

IDR_WINDIVERT_DLL       RCDATA      "windivert_sdk\\bin\\x64\\WinDivert.dll"
IDR_WINDIVERT64_SYS     RCDATA      "windivert_sdk\\bin\\x64\\WinDivert64.sys"
IDR_WINDIVERT_SYS       RCDATA      "windivert_sdk\\bin\\x64\\WinDivert.sys"

```

### Шаг 4. Компиляция

1. Откройте проект/решение в Visual Studio 2022.

2. Выберите конфигурацию **Release** и платформу **x64**.

3. Убедитесь, что в свойствах компилятора (`C/C++` → `Command Line`) указан флаг `/utf-8`, а стандарт C++ установлен на `ISO C++20` (`stdcpp20`).

4. Выполните сборку: **Build** → **Build Solution** (или `Ctrl + Shift + B`).

5. Итоговый исполняемый файл будет доступен в папке `bin\Release\`.

## Благодарности и кредиты

* **bol-van** / [zapret](https://github.com/bol-van/zapret) — за исследования сигнатур сетевого оборудования и идеи обхода DPI.

* **basil00** / [WinDivert](https://reqrypt.org/windivert.html) — за драйвер перехвата и модификации сетевых пакетов пользовательского уровня для Windows.

* **ValdikSS** / [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) — за фундаментальные наработки в области десинхронизации TCP и анализа сетевых фильтров.
