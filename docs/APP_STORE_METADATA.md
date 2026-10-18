# App Store metadata — SecCorp 1.0

## Shared

- App name: `SecCorp`
- Bundle ID: `com.webnetkz.seccom`
- SKU: `seccorp-2026`
- Primary language: Russian
- Category: Utilities
- Price: Free
- Copyright: `2026 webnetkz`
- Support URL: `https://github.com/webnetkz/seccorp/issues`
- Privacy policy URL: `https://github.com/webnetkz/seccorp/blob/main/docs/PRIVACY.md`
- App privacy: Data Not Collected
- Encryption: uses only exempt encryption provided by the operating system (HTTPS and local data protection); `ITSAppUsesNonExemptEncryption = NO`

## iOS — Russian

- Subtitle: `Локальная проверка файлов`
- Promotional text: `Проверяйте документы, архивы и другие файлы локально — без отправки содержимого на сервер.`
- Keywords: `файлы,сканер,безопасность,архивы,проверка,карантин,вредоносные файлы`

Description:

> SecCorp помогает проверить безопасность файлов прямо на iPhone и iPad.
>
> Выберите файл в приложении «Файлы» или передайте его через меню «Поделиться». SecCorp локально проверит хеши, сигнатуры содержимого, архивы и подозрительные признаки. Содержимое файлов и результаты проверки не отправляются на сервер.
>
> Возможности:
> - проверка выбранных файлов;
> - сигнатурный и эвристический анализ;
> - безопасная проверка ZIP, GZIP, TAR, APK, JAR и документов Office;
> - локальный зашифрованный карантин;
> - обновляемые подписанные базы угроз;
> - проверка доступных настроек безопасности устройства;
> - русский и английский интерфейс, светлая и темная темы.
>
> Из-за ограничений iOS SecCorp не сканирует систему и данные других приложений. Проверяются только файлы, которые вы явно выбрали или передали приложению.

## iOS — English

- Subtitle: `Private local file scanner`
- Promotional text: `Check documents, archives, and other files locally without uploading their contents.`
- Keywords: `file,scanner,security,archive,check,quarantine,malware,privacy`

Description:

> SecCorp helps you check files directly on iPhone and iPad.
>
> Select a file in the Files app or send it through the Share menu. SecCorp checks hashes, content signatures, archives, and suspicious characteristics locally. File contents and scan results are not uploaded.
>
> Features:
> - scan selected files;
> - signature and heuristic analysis;
> - guarded inspection of ZIP, GZIP, TAR, APK, JAR, and Office documents;
> - encrypted local quarantine;
> - signed threat-database updates;
> - checks of available device-security settings;
> - English and Russian interface, light and dark themes.
>
> Because of iOS restrictions, SecCorp cannot scan the operating system or other apps' private data. It checks only files that you explicitly select or share with the app.

## Android — Russian

- Short description: `Локальная проверка файлов, приложений и безопасности Android.`
- Category: `Инструменты`

Description:

> SecCorp — локальный сканер безопасности для Android. Проверяйте файлы, архивы и установленные приложения прямо на устройстве: содержимое и результаты проверки не отправляются на сервер.
>
> Возможности:
> - быстрая, полная и выборочная проверка файлов;
> - проверка установленных приложений и их разрешений;
> - сигнатурный и эвристический анализ;
> - безопасная проверка ZIP, GZIP, TAR, APK, JAR и документов Office;
> - фоновая защита новых загрузок и установок;
> - локальный зашифрованный карантин;
> - проверка настроек безопасности устройства;
> - русский и английский интерфейс, светлая и тёмная темы.
>
> Для полной проверки SecCorp может запросить доступ ко всем файлам и сведениям об установленных приложениях. Эти разрешения используются только для основных функций антивирусного сканера. Все данные обрабатываются локально и не передаются webnetkz или третьим лицам.

## Android — English

- Short description: `Private local scanner for Android files, apps, and device security.`
- Category: `Tools`

Description:

> SecCorp is a local security scanner for Android. Check files, archives, and installed apps directly on your device without uploading file contents or scan results.
>
> Features:
> - quick, full, and custom file scans;
> - installed-app and permission checks;
> - signature and heuristic analysis;
> - guarded inspection of ZIP, GZIP, TAR, APK, JAR, and Office documents;
> - background protection for new downloads and app installations;
> - local encrypted quarantine;
> - device-security checks;
> - English and Russian interfaces with light and dark themes.
>
> For full scans, SecCorp may request access to all files and information about installed apps. These permissions are used only for the antivirus scanner's core functionality. All data is processed locally and is not shared with webnetkz or third parties.

## macOS — Russian

- Subtitle: `Проверка файлов и папок`
- Promotional text: `Локально проверяйте выбранные файлы и папки с помощью сигнатурного и эвристического анализа.`
- Keywords: `файлы,папки,сканер,безопасность,архивы,карантин,проверка`

Description:

> SecCorp — локальный сканер безопасности для выбранных файлов и папок на Mac.
>
> Приложение использует сигнатурный и эвристический анализ, проверяет содержимое архивов и помогает изолировать найденные угрозы в зашифрованном карантине. Файлы и результаты проверки не загружаются на сервер.
>
> Версия из Mac App Store работает в песочнице Apple и получает доступ только к тем файлам и папкам, которые вы явно выбрали. Для защиты всего диска, мониторинга файлов в реальном времени, подключаемых носителей и сетевых соединений используйте прямую версию SecCorp с сайта разработчика.

## macOS — English

- Subtitle: `Scan selected files and folders`
- Promotional text: `Scan selected files and folders locally with signature and heuristic analysis.`
- Keywords: `file,folder,scanner,security,archive,quarantine,malware,privacy`

Description:

> SecCorp is a local security scanner for files and folders you select on your Mac.
>
> It uses signature and heuristic analysis, inspects supported archives, and can isolate detections in encrypted quarantine. Files and scan results are not uploaded.
>
> The Mac App Store version runs inside Apple's sandbox and can access only files and folders that you explicitly select. Whole-disk protection, real-time file monitoring, removable-media checks, and network-connection monitoring remain available in the direct version of SecCorp from the developer.

## Review notes

SecCorp does not claim system-wide protection on iOS. Use the system document picker to select a sample file. The Mac App Store binary is the sandboxed `mac-app-store` build and scans only user-selected items. The included EICAR string can be used to verify detection without real malware.
