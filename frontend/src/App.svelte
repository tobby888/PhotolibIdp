<script>
  import { onMount } from 'svelte'
  import Applications from './Applications.svelte'
  import RegistrationCodes from './RegistrationCodes.svelte'
  import RegistrationReview from './RegistrationReview.svelte'
  import Users from './Users.svelte'
  import { api } from './api.js'

  const adminSections = [
    { id: 'users', label: '账号管理' },
    { id: 'apps', label: '应用注册与准入' },
    { id: 'codes', label: '注册码' },
    { id: 'reviews', label: '注册审核' },
    { id: 'settings', label: '标语与个人安全' },
  ]
  const memberSections = [
    { id: 'apps', label: '可访问应用' },
    { id: 'settings', label: '个人安全' },
  ]

  function parseHash() {
    const raw = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash
    const [routePart, queryPart = ''] = raw.split('?')
    return { route: routePart || 'users', query: queryPart || location.search.slice(1) }
  }

  let parsed = $state(parseHash())
  let user = $state(null)
  let accessibleApps = $state([])
  let slogan = $state('统一身份认证与访问准入中心')
  let sloganInput = $state('统一身份认证与访问准入中心')
  let loading = $state(true)
  let busy = $state(false)
  let error = $state('')
  let feedback = $state('')
  let registerSubmitted = $state(null)
  let oauthContext = $state(null)
  let oauthLoading = $state(false)

  let availableSections = $derived(user?.admin ? adminSections : memberSections)
  let active = $derived(availableSections.find(s => s.id === parsed.route) ?? availableSections[0])

  async function loadSettings() {
    try {
      const s = await api('/api/v1/settings')
      if (s?.slogan) {
        slogan = s.slogan
        sloganInput = s.slogan
      }
    } catch {
      // keep default slogan
    }
  }

  async function loadSession() {
    loading = true
    error = ''
    try {
      await loadSettings()
      const me = await api('/api/v1/auth/me')
      user = me.user
      accessibleApps = me.apps || []
      if (me.slogan) {
        slogan = me.slogan
        sloganInput = me.slogan
      }
      if (parsed.route === 'authorize' && !user.mustChangePassword) {
        await inspectOAuth()
      }
    } catch {
      user = null
    } finally {
      loading = false
    }
  }

  async function inspectOAuth() {
    oauthLoading = true
    oauthContext = null
    error = ''
    try {
      oauthContext = await api('/api/v1/oauth/authorize?' + parsed.query)
    } catch (err) {
      error = err.message
    } finally {
      oauthLoading = false
    }
  }

  onMount(() => { void loadSession() })

  function onHashChange() {
    parsed = parseHash()
    error = ''
    feedback = ''
    if (user && !user.mustChangePassword && parsed.route === 'authorize') {
      void inspectOAuth()
    }
  }

  async function signIn(event) {
    event.preventDefault()
    if (busy) return
    const data = Object.fromEntries(new FormData(event.currentTarget))
    busy = true
    error = ''
    try {
      await api('/api/v1/auth/login', {
        method: 'POST',
        body: { username: data.username, password: data.password },
      })
      await loadSession()
    } catch (err) {
      error = err.message
    } finally {
      busy = false
    }
  }

  async function submitRegister(event) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const data = Object.fromEntries(new FormData(form))
    busy = true
    error = ''
    try {
      registerSubmitted = await api('/api/v1/public/registrations', {
        method: 'POST',
        body: {
          code: data.code,
          username: data.username,
          displayName: data.displayName,
          email: data.email,
          password: data.password,
          confirmPassword: data.confirmPassword,
        },
      })
      form.reset()
    } catch (err) {
      error = err.message
    } finally {
      busy = false
    }
  }

  async function submitInitialPassword(event) {
    event.preventDefault()
    if (busy) return
    const data = Object.fromEntries(new FormData(event.currentTarget))
    if (data.newPassword !== data.confirmPassword) {
      error = '两次输入的新密码不一致'
      return
    }
    busy = true
    error = ''
    try {
      user = await api('/api/v1/auth/initial-password', {
        method: 'PUT',
        body: { initialPassword: data.initialPassword, newPassword: data.newPassword },
      })
      if (parsed.route === 'authorize') {
        await inspectOAuth()
      }
    } catch (err) {
      error = err.message
    } finally {
      busy = false
    }
  }

  async function approveOAuth() {
    if (busy) return
    const q = new URLSearchParams(parsed.query)
    busy = true
    error = ''
    try {
      const res = await api('/api/v1/oauth/authorize', {
        method: 'POST',
        body: {
          clientId: q.get('client_id') || '',
          redirectUri: q.get('redirect_uri') || '',
          state: q.get('state') || '',
          codeChallenge: q.get('code_challenge') || q.get('challenge') || '',
        },
      })
      location.replace(res.callbackUrl)
    } catch (err) {
      error = err.message
      busy = false
    }
  }

  async function saveSlogan(event) {
    event.preventDefault()
    if (busy) return
    busy = true
    error = ''
    feedback = ''
    try {
      const res = await api('/api/v1/settings', {
        method: 'PUT',
        body: { slogan: sloganInput },
      })
      slogan = res.slogan
      sloganInput = res.slogan
      feedback = '已更新认证中心标语'
    } catch (err) {
      error = err.message
    } finally {
      busy = false
    }
  }

  async function changePassword(event) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const data = Object.fromEntries(new FormData(form))
    if (data.newPassword !== data.confirmPassword) {
      error = '两次输入的新密码不一致'
      return
    }
    busy = true
    error = ''
    feedback = ''
    try {
      await api('/api/v1/auth/password', {
        method: 'PUT',
        body: { oldPassword: data.oldPassword, newPassword: data.newPassword },
      })
      form.reset()
      feedback = '密码已更新'
    } catch (err) {
      error = err.message
    } finally {
      busy = false
    }
  }

  function expire() {
    user = null
    error = '会话已过期，请重新登录。'
  }

  async function logout() {
    try {
      await api('/api/v1/auth/logout', { method: 'POST' })
    } finally {
      user = null
      location.hash = '#login'
    }
  }
</script>

<svelte:window onhashchange={onHashChange} />

{#if loading}
  <main class="login">
    <section class="login-card">
      <div class="brand"><span>PhotolibIdp</span><small>{slogan}</small></div>
      <p style="margin-top:20px" role="status">正在检查登录状态…</p>
    </section>
  </main>
{:else if !user && parsed.route === 'register'}
  <main class="login">
    <section class="login-card">
      <div class="brand"><span>PhotolibIdp</span><small>{slogan}</small></div>
      <h1>使用注册码注册账号</h1>
      {#if registerSubmitted}
        <p class="notice success" role="status">
          {registerSubmitted.displayName}，你的账号 <code>@{registerSubmitted.username}</code> 注册申请已提交，正在等待管理员审核。审核通过后即可使用该账号登录。
        </p>
        <div class="login-actions">
          <a class="button primary" href="#login" onclick={() => registerSubmitted = null}>返回登录</a>
        </div>
      {:else}
        <p>注册码由管理员发放。提交申请后需经管理员审核通过方可登录。</p>
        {#if error}<p class="notice danger" role="alert">{error}</p>{/if}
        <form class="form-stack" onsubmit={submitRegister}>
          <label>注册码 <input name="code" required placeholder="16 位注册码（支持带连字符）" autocomplete="off" /></label>
          <label>
            登录账号
            <input name="username" required pattern="[A-Za-z0-9_.-]{3,64}" placeholder="3-64 位字母、数字或 ._-" autocomplete="username" />
          </label>
          <label>真实姓名 <input name="displayName" required maxlength="50" placeholder="请如实填写真实姓名，用于管理员审核" autocomplete="name" /></label>
          <label>邮箱 <input name="email" type="email" required maxlength="255" placeholder="name@example.com" autocomplete="email" /></label>
          <label>密码 <input name="password" type="password" required minlength="10" maxlength="72" placeholder="至少 10 位，同时包含字母和数字" autocomplete="new-password" /></label>
          <label>确认密码 <input name="confirmPassword" type="password" required minlength="10" maxlength="72" placeholder="再次输入密码" autocomplete="new-password" /></label>
          <div class="login-actions">
            <button type="submit" class="button primary" disabled={busy}>提交注册申请</button>
            <a class="button" href="#login">已有账号，返回登录</a>
          </div>
        </form>
      {/if}
    </section>
  </main>
{:else if !user}
  <main class="login">
    <section class="login-card">
      <div class="brand"><span>PhotolibIdp</span><small>{slogan}</small></div>
      <h1>登录统一身份认证中心</h1>
      <p>使用你的账号或邮箱登录。</p>
      {#if error}<p class="notice danger" role="alert">{error}</p>{/if}
      <form class="form-stack" onsubmit={signIn}>
        <label>账号或邮箱 <input name="username" required autocomplete="username" placeholder="请输入登录账号或邮箱" /></label>
        <label>密码 <input name="password" type="password" required autocomplete="current-password" placeholder="请输入密码" /></label>
        <div class="login-actions">
          <button type="submit" class="button primary" disabled={busy}>登录</button>
          <a class="button" href="#register">有注册码？申请注册账号</a>
        </div>
      </form>
    </section>
  </main>
{:else if user.mustChangePassword}
  <main class="login">
    <section class="login-card">
      <div class="brand"><span>PhotolibIdp</span><small>{slogan}</small></div>
      <h1>首次登录请修改初始密码</h1>
      <p>为了账号安全，请先将管理员发放的一次性初始密码修改为你自己的密码。</p>
      {#if error}<p class="notice danger" role="alert">{error}</p>{/if}
      <form class="form-stack" onsubmit={submitInitialPassword}>
        <label>初始密码 <input name="initialPassword" type="password" required autocomplete="current-password" /></label>
        <label>新密码 <input name="newPassword" type="password" required minlength="10" maxlength="72" placeholder="至少 10 位，包含字母和数字" autocomplete="new-password" /></label>
        <label>确认新密码 <input name="confirmPassword" type="password" required minlength="10" maxlength="72" autocomplete="new-password" /></label>
        <div class="login-actions">
          <button type="submit" class="button primary" disabled={busy}>保存新密码并继续</button>
          <button type="button" class="button" onclick={logout}>退出登录</button>
        </div>
      </form>
    </section>
  </main>
{:else if parsed.route === 'authorize'}
  <main class="login">
    <section class="login-card">
      <div class="brand"><span>PhotolibIdp</span><small>{slogan}</small></div>
      <h1>单点登录授权</h1>
      {#if oauthLoading}
        <p role="status">正在核对应用注册信息与访问权限…</p>
      {:else if error}
        <p class="notice danger" role="alert">{error}</p>
        <div class="login-actions">
          <a class="button" href="#users">进入认证中心控制台</a>
        </div>
      {:else if oauthContext}
        <p>当前登录账号：<strong>{oauthContext.user.displayName}</strong> (<code>@{oauthContext.user.username}</code>)</p>
        {#if !oauthContext.allowed}
          <p class="notice danger" role="alert">
            当前账号未获授权访问应用「{oauthContext.app.name}」，请联系管理员在统一认证中心将该账号加入应用准入名单。
          </p>
          <div class="login-actions">
            <a class="button" href="#apps">返回认证中心</a>
            <button type="button" class="button" onclick={logout}>切换账号</button>
          </div>
        {:else}
          <p>即将使用你的统一认证账号登录 <strong>{oauthContext.app.name}</strong>。</p>
          <div class="login-actions">
            <button class="button primary" disabled={busy} onclick={approveOAuth}>授权并登录 {oauthContext.app.name}</button>
            <button type="button" class="button" onclick={logout}>切换账号</button>
          </div>
        {/if}
      {/if}
    </section>
  </main>
{:else}
  <div class="layout">
    <aside class="sidebar">
      <a class="brand" href={'#' + availableSections[0].id}>
        <span>PhotolibIdp</span>
        <small>{slogan}</small>
      </a>
      <nav aria-label="认证中心导航">
        {#each availableSections as item (item.id)}
          <a href={'#' + item.id} aria-current={active.id === item.id ? 'page' : undefined}>{item.label}</a>
        {/each}
      </nav>
    </aside>
    <main class="workspace">
      <header class="topbar">
        <span><strong>PhotolibIdp</strong> <span class="muted">/ {slogan}</span></span>
        <div class="account">
          <span>{user.displayName} (<code>@{user.username}</code>)</span>
          <button class="button compact" onclick={logout}>退出</button>
        </div>
      </header>
      <section class="content" aria-labelledby="section-title">
        <div class="page-heading">
          <h1 id="section-title">{active.label}</h1>
        </div>
        {#if user.admin && active.id === 'users'}
          <Users currentUser={user} onExpired={expire} />
        {:else if user.admin && active.id === 'apps'}
          <Applications onExpired={expire} />
        {:else if user.admin && active.id === 'codes'}
          <RegistrationCodes onExpired={expire} />
        {:else if user.admin && active.id === 'reviews'}
          <RegistrationReview onExpired={expire} />
        {:else if !user.admin && active.id === 'apps'}
          <section class="panel">
            <div class="panel-heading">
              <div>
                <h2>已授权访问的服务</h2>
                <p class="muted">当前账号在统一认证中心获准访问以下应用服务。</p>
              </div>
            </div>
            {#if !accessibleApps.length}
              <p class="empty">当前暂无可访问的应用服务，请联系管理员授权。</p>
            {/if}
            {#each accessibleApps as app (app.id)}
              <div class="row">
                <div class="row-content">
                  <div class="row-title">
                    <strong>{app.name}</strong>
                    <code>{app.clientId}</code>
                  </div>
                  {#if app.description}<p class="muted">{app.description}</p>{/if}
                </div>
                {#if app.homepageUrl}
                  <a class="button compact primary" href={app.homepageUrl} target="_blank" rel="noreferrer">打开应用 ↗</a>
                {/if}
              </div>
            {/each}
          </section>
        {:else}
          {#if error}<p class="notice danger" role="alert">{error}</p>{/if}
          {#if feedback}<p class="notice success" role="status">{feedback}</p>{/if}
          {#if user.admin}
            <section class="panel">
              <div class="panel-heading">
                <div>
                  <h2>认证中心标语设置</h2>
                  <p class="muted">PhotolibIdp 不设图标，仅展示管理员设置的标语。</p>
                </div>
              </div>
              <div class="row">
                <form class="form-stack" style="width:min(100%, 520px)" onsubmit={saveSlogan}>
                  <label>
                    当前标语
                    <input bind:value={sloganInput} required maxlength="120" placeholder="请输入认证中心标语" />
                  </label>
                  <div><button type="submit" class="button primary" disabled={busy}>保存标语</button></div>
                </form>
              </div>
            </section>
          {/if}
          <section class="panel">
            <div class="panel-heading">
              <div>
                <h2>修改登录密码</h2>
                <p class="muted">新密码至少 10 位，且同时包含字母和数字。</p>
              </div>
            </div>
            <div class="row">
              <form class="form-stack" style="width:min(100%, 420px)" onsubmit={changePassword}>
                <label>当前密码 <input name="oldPassword" type="password" required autocomplete="current-password" /></label>
                <label>新密码 <input name="newPassword" type="password" required minlength="10" maxlength="72" autocomplete="new-password" /></label>
                <label>确认新密码 <input name="confirmPassword" type="password" required minlength="10" maxlength="72" autocomplete="new-password" /></label>
                <div><button type="submit" class="button primary" disabled={busy}>更新密码</button></div>
              </form>
            </div>
          </section>
        {/if}
      </section>
    </main>
  </div>
{/if}
