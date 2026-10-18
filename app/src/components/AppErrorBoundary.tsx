import { Component, type ErrorInfo, type ReactNode } from "react";

interface State {
  error: Error | null;
}

export class AppErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("SecCorp interface failed to start", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;

    const russian = navigator.language.toLowerCase().startsWith("ru");
    return (
      <main className="startup-error" role="alert">
        <div className="startup-error__card">
          <div className="startup-error__logo">S</div>
          <h1>SecCorp</h1>
          <h2>{russian ? "Не удалось запустить интерфейс" : "The interface could not start"}</h2>
          <p>
            {russian
              ? "Перезапустите приложение. Если ошибка повторится, отправьте файл журнала разработчику."
              : "Restart the app. If the problem continues, send the startup log to the developer."}
          </p>
          <code>%LOCALAPPDATA%\SecCorp\logs\startup.log</code>
        </div>
      </main>
    );
  }
}
