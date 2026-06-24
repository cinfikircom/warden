import type { StackDetector } from "../types.ts";

/** Python / Django. */
export const djangoDetector: StackDetector = {
  id: "django",
  priority: 80,
  async detect(ctx) {
    if (!ctx.exists("manage.py")) return null;
    const req = ctx.readFile("requirements.txt") ?? "";
    const pyproject = ctx.readFile("pyproject.toml") ?? "";
    const hasDjango = /django/i.test(req) || /django/i.test(pyproject) || ctx.exists("manage.py");
    if (!hasDjango) return null;
    return { languages: ["python"], frameworks: ["django"], orm: ["django-orm"], signals: {} };
  },
};

/** PHP / Laravel (adaptör Faz 6; burada yalnızca tespit). */
export const laravelDetector: StackDetector = {
  id: "laravel",
  priority: 80,
  async detect(ctx) {
    if (!ctx.exists("artisan")) return null;
    const composer = ctx.readFile("composer.json") ?? "";
    const isLaravel = /laravel\/framework/.test(composer) || ctx.exists("artisan");
    if (!isLaravel) return null;
    return {
      languages: ["php"],
      frameworks: ["laravel"],
      orm: ["eloquent"],
      signals: {
        hasSanctum: /laravel\/sanctum/.test(composer),
        hasPassport: /laravel\/passport/.test(composer),
        hasTelescope: /laravel\/telescope/.test(composer),
        hasHorizon: /laravel\/horizon/.test(composer),
      },
    };
  },
};

/** .NET / ASP.NET (adaptör Faz 6; burada yalnızca tespit). */
export const aspnetDetector: StackDetector = {
  id: "aspnet",
  priority: 80,
  async detect(ctx) {
    const csproj = ctx.find((p) => p.endsWith(".csproj"), { limit: 50 });
    if (csproj.length === 0) return null;
    const anyAspNet = csproj.some((p) => /Microsoft\.AspNetCore|Sdk="Microsoft\.NET\.Sdk\.Web"/.test(ctx.readFile(p) ?? ""));
    return {
      languages: ["csharp"],
      frameworks: anyAspNet ? ["aspnet"] : [],
      orm: csproj.some((p) => /EntityFrameworkCore/.test(ctx.readFile(p) ?? "")) ? ["ef-core"] : [],
      signals: { projects: csproj },
    };
  },
};

/** Go. */
export const goDetector: StackDetector = {
  id: "go",
  priority: 80,
  async detect(ctx) {
    const mod = ctx.readFile("go.mod");
    if (!mod) return null;
    const orm: string[] = [];
    if (/gorm\.io\/gorm/.test(mod)) orm.push("gorm");
    return { languages: ["go"], orm, signals: {} };
  },
};
