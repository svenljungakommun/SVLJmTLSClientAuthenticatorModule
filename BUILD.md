# BUILD Instructions – SVLJmTLSClientAuthenticatorModule

This document describes how to build the `SVLJ.Security.dll` library from source using Visual Studio.
The library implements strict mTLS (mutual TLS) client/server validation for outbound HTTPS connections using `HttpClient` on .NET Framework 4.8.

---

## 📦 Prerequisites

- Windows 10/11 or Windows Server 2016/2019/2022  
- [Visual Studio 2019 or 2022](https://visualstudio.microsoft.com/)  
  - Workload: **.NET desktop development**  
- .NET Framework 4.8 Developer Pack (included in recent VS versions)  
- For .NET 6/7/8 builds: install the [.NET SDK](https://dotnet.microsoft.com/download) for the required version

---

## 📁 Project Structure

You will be creating this structure manually:

```
SVLJmTLSClientAuthenticatorModule
├── SVLJmTLSClientAuthenticatorModule.cs
├── SVLJ.Security.csproj
├── SVLJ.Security.sln
├── Properties
│   └── AssemblyInfo.cs
```

---

## 🧰 Build Steps

### 1. Create a Class Library project

1. Launch **Visual Studio**
2. Click `File → New → Project`
3. Select: **Class Library (.NET Framework)**
4. Name the project: `SVLJ.Security`
5. Select framework version: `.NET Framework 4.8`
6. Finish and create the solution

### 2. Add the source file

1. Download or copy `SVLJmTLSClientAuthenticatorModule.cs`
2. Place it in the project directory
3. In Solution Explorer:

   * Right-click the project → `Add → Existing Item`
   * Select `SVLJmTLSClientAuthenticatorModule.cs`

### 3. Optional: Add `AssemblyInfo.cs`

Create `Properties\AssemblyInfo.cs` with content like:

```csharp
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("SVLJ.Security")]
[assembly: AssemblyDescription("SVLJ Mutual TLS Authenticator Module")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Svenljunga kommun")]
[assembly: AssemblyProduct("SVLJ.Security")]
[assembly: AssemblyCopyright("Copyright © Svenljunga kommun 2025")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
[assembly: ComVisible(false)]
[assembly: Guid("e8c9ac63-6e75-482a-a70b-2e7f5f154f52")]
[assembly: AssemblyVersion("0.4.0.0")]
[assembly: AssemblyFileVersion("0.4.0.0")]
```

### 4. Build the DLL

1. Set build configuration to `Release`
2. Press `Ctrl+Shift+B` or go to `Build → Build Solution`
3. Output file will be:

```
<project path>\bin\Release\SVLJ.Security.dll
```

### 5. Sign the DLL (Recommended)

To ensure integrity and authenticity of the built library, sign the output DLL using `signtool.exe`, included with the **Windows SDK**.

1. **Locate `signtool.exe`**
   Typically found at:
   `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe`

2. **Run the signing command**:

   ```bash
   signtool sign ^
     /f "certificate.pfx" ^
     /p <password> ^
     /tr http://timestamp.digicert.com ^
     /td sha256 ^
     /fd sha256 ^
     "<project path>\bin\Release\SVLJ.Security.dll"
   ```

---

## 🚀 Deployment

Since this module is a client-side library:

1. Copy `SVLJ.Security.dll` into your application’s `bin\` directory (or package it via NuGet if desired).
2. Ensure you have a valid `web.config` or `app.config` containing the required `<appSettings>` (see README).
3. Distribute supporting files like CA bundles (`ca-bundle.pem`) into secure application directories.

---

## 🔍 Verifying the DLL

You can test the module by:

* Creating a small console app that calls a protected API using `SVLJmTLSClientAuthenticatorModule.FromConfig()`
* Ensuring that invalid or expired server certificates are **blocked**
* Confirming that a valid client PFX + trusted server connection succeeds

---

## 📝 Notes

* The project has **no NuGet dependencies**
* It is designed for **self-hosted, air-gapped, or public sector environments**
* You may strong-name the DLL if required for GAC or binding redirects
