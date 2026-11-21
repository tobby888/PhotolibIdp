<script>
  import { onMount } from 'svelte'
  import { api, date } from './api.js'

  let { onExpired } = $props()
  let apps = $state([])
  let users = $state([])
  let loading = $state(true)
  let error = $state('')
  let feedback = $state('')
  let issuedSecret = $state(null)
  let busy = $state(false)

  let createDialog
  let editDialog
  let createPolicy = $state('ALL_AUTHENTICATED')
  let createAllowedUsers = $state([])
  let editing = $state(null)

  async function reload() {
    loading = true
    error = ''
    try {
      const [appList, userList] = await Promise.all([api('/api/v1/apps'), api('/api/v1/users')])
      apps = appList
      users = userList
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      loading = false
    }
  }

  onMount(() => { void reload() })

  function toggleSelection(list, id) {
    return list.includes(id) ? list.filter(x => x !== id) : [...list, id]
  }

  async function createApp(event) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const data = Object.fromEntries(new FormData(form))
    busy = true
    error = ''
    try {
      const redirectUris = String(data.redirectUris || '').split(/\r?\n|,/).map(s => s.trim()).filter(Boolean)
      const res = await api('/api/v1/apps', {
        method: 'POST',
        body: {
          name: data.name,
          clientId: data.clientId || '',
          description: data.description || '',
          redirectUris,
          homepageUrl: data.homepageUrl || '',
          accessPolicy: createPolicy,
          allowedUserIds: createPolicy === 'RESTRICTED' ? createAllowedUsers : [],
        },
      })
      form.reset()
      createPolicy = 'ALL_AUTHENTICATED'
      createAllowedUsers = []
      createDialog.close()
      issuedSecret = { name: res.app.name, clientId: res.app.clientId, clientSecret: res.clientSecret }
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  function openEdit(app) {
    editing = {
      ...app,
      redirectUrisText: (app.redirectUris || []).join('\n'),
      allowedUserIds: [...(app.allowedUserIds || [])],
    }
    editDialog.showModal()
  }

  async function saveEdit(event) {
    event.preventDefault()
    if (busy || !editing) return
    busy = true
    error = ''
    try {
      const redirectUris = String(editing.redirectUrisText || '').split(/\r?\n|,/).map(s => s.trim()).filter(Boolean)
      await api(`/api/v1/apps/${editing.id}`, {
        method: 'PUT',
        body: {
          name: editing.name,
          description: editing.description || '',
          redirectUris,
          homepageUrl: editing.homepageUrl || '',
          accessPolicy: editing.accessPolicy,
          allowedUserIds: editing.accessPolicy === 'RESTRICTED' ? editing.allowedUserIds : [],
          enabled: Boolean(editing.enabled),
          version: editing.version,
        },
      })
      editDialog.close()
      feedback = `已保存应用「${editing.name}」的注册配置与准入名单`
      editing = null
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  async function rotateSecret(app) {
    if (busy || !confirm(`确定重新生成应用「${app.name}」的 Client Secret 吗？旧密钥将立即失效。`)) return
    busy = true
    error = ''
    try {
      const res = await api(`/api/v1/apps/${app.id}/secret`, { method: 'POST' })
      issuedSecret = { name: res.app.name, clientId: res.app.clientId, clientSecret: res.clientSecret }
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  async function removeApp(app) {
    if (busy || !confirm(`确定删除应用「${app.name}」(${app.clientId}) 吗？`)) return
    busy = true
    error = ''
    try {
      await api(`/api/v1/apps/${app.id}`, { method: 'DELETE' })
      feedback = `已删除应用「${app.name}」`
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }
</script>

{#if error}<p class="notice danger" role="alert">{error}</p>{/if}
{#if feedback}<p class="notice success" role="status">{feedback}</p>{/if}
{#if issuedSecret}
  <div class="secret-box" role="status">
    <strong>应用「{issuedSecret.name}」已生成凭证（Client Secret 仅显示一次，请立即复制到对应服务的配置文件）：</strong>
    <p>Client ID: <code>{issuedSecret.clientId}</code></p>
    <p>Client Secret: <code>{issuedSecret.clientSecret}</code></p>
    <button class="button compact" onclick={() => issuedSecret = null}>我已保存</button>
  </div>
{/if}

<section class="panel">
  <div class="panel-heading">
    <div>
      <h2>应用注册与访问准入</h2>
      <p class="muted">注册业务服务（如 PhotoLib、Deplyt），生成 Client ID 与密钥、配置回调 URL，并控制哪些账号允许登录该服务。</p>
    </div>
    <button class="button primary" onclick={() => createDialog.showModal()}>注册新应用</button>
  </div>
  {#if loading && !apps.length}
    <p class="empty">正在读取应用列表…</p>
  {:else if !apps.length}
    <p class="empty">尚未注册任何应用。点击右上角「注册新应用」添加 PhotoLib 或 Deplyt。</p>
  {/if}
  {#each apps as app (app.id)}
    <div class="row">
      <div class="row-content">
        <div class="row-title">
          <strong>{app.name}</strong>
          <code>Client ID: {app.clientId}</code>
          <span class={'status ' + (app.enabled ? 'succeeded' : 'failed')}>{app.enabled ? '启用' : '已停用'}</span>
          <span class="status running">{app.accessPolicy === 'ALL_AUTHENTICATED' ? '全部启用账号可访问' : `仅限指定名单与管理员（${app.allowedUserIds?.length || 0} 人）`}</span>
        </div>
        {#if app.description}<p class="muted" style="margin-top:4px">{app.description}</p>{/if}
        <div class="metadata">
          <span>回调 URL: {#each app.redirectUris as uri, idx}{idx ? '、' : ''}<code>{uri}</code>{/each}</span>
          {#if app.homepageUrl}<span>主页: <code>{app.homepageUrl}</code></span>{/if}
          <span>更新于 {date(app.updatedAt)}</span>
        </div>
      </div>
      <div class="login-actions">
        <button class="button compact" disabled={busy} onclick={() => openEdit(app)}>配置与准入名单</button>
        <button class="button compact" disabled={busy} onclick={() => rotateSecret(app)}>重置密钥</button>
        <button class="button compact destructive" disabled={busy} onclick={() => removeApp(app)}>删除</button>
      </div>
    </div>
  {/each}
</section>

<dialog bind:this={createDialog}>
  <form onsubmit={createApp}>
    <h2>注册新应用</h2>
    <div class="form-stack">
      <label>应用名称 <input name="name" required maxlength="100" placeholder="例如 PhotoLib 或 Deplyt" /></label>
      <label>
        Client ID（可选，留空自动生成）
        <input name="clientId" pattern="[A-Za-z0-9_.-]{3,64}" placeholder="例如 photolib 或 deplyt" />
      </label>
      <label>应用说明（可选） <input name="description" maxlength="200" placeholder="例如 摄影部图片工作站" /></label>
      <label>
        回调 URL（每行一个，须为完整 HTTPS 地址）
        <textarea name="redirectUris" rows="3" required placeholder="https://photolib.example.com/auth/callback"></textarea>
      </label>
      <label>应用主页 URL（可选） <input name="homepageUrl" placeholder="https://photolib.example.com" /></label>
      <label>
        访问准入策略
        <select bind:value={createPolicy}>
          <option value="ALL_AUTHENTICATED">允许全部已启用的认证中心账号登录</option>
          <option value="RESTRICTED">仅允许管理员和下方勾选的账号登录</option>
        </select>
      </label>
      {#if createPolicy === 'RESTRICTED'}
        <div>
          <span style="font-size:.9rem;font-weight:600">允许访问此应用的账号（管理员默认拥有访问权）</span>
          <div class="user-checklist">
            {#each users as u (u.id)}
              <label class="checkbox-inline">
                <input type="checkbox" checked={createAllowedUsers.includes(u.id)} onchange={() => createAllowedUsers = toggleSelection(createAllowedUsers, u.id)} />
                <span>{u.displayName} (<code>@{u.username}</code>){u.admin ? ' · 管理员' : ''}</span>
              </label>
            {/each}
          </div>
        </div>
      {/if}
    </div>
    <div class="dialog-actions">
      <button type="button" class="button" onclick={() => createDialog.close()}>取消</button>
      <button type="submit" class="button primary" disabled={busy}>注册并生成密钥</button>
    </div>
  </form>
</dialog>

<dialog bind:this={editDialog}>
  {#if editing}
    <form onsubmit={saveEdit}>
      <h2>配置应用 · {editing.name}</h2>
      <div class="form-stack">
        <label>Client ID <input value={editing.clientId} disabled /></label>
        <label>应用名称 <input bind:value={editing.name} required maxlength="100" /></label>
        <label>应用说明 <input bind:value={editing.description} maxlength="200" /></label>
        <label>
          回调 URL（每行一个）
          <textarea bind:value={editing.redirectUrisText} rows="3" required></textarea>
        </label>
        <label>应用主页 URL <input bind:value={editing.homepageUrl} /></label>
        <label>
          访问准入策略
          <select bind:value={editing.accessPolicy}>
            <option value="ALL_AUTHENTICATED">允许全部已启用的认证中心账号登录</option>
            <option value="RESTRICTED">仅允许管理员和下方勾选的账号登录</option>
          </select>
        </label>
        {#if editing.accessPolicy === 'RESTRICTED'}
          <div>
            <span style="font-size:.9rem;font-weight:600">允许访问此应用的账号（管理员默认拥有访问权）</span>
            <div class="user-checklist">
              {#each users as u (u.id)}
                <label class="checkbox-inline">
                  <input type="checkbox" checked={editing.allowedUserIds.includes(u.id)} onchange={() => editing.allowedUserIds = toggleSelection(editing.allowedUserIds, u.id)} />
                  <span>{u.displayName} (<code>@{u.username}</code>){u.admin ? ' · 管理员' : ''}</span>
                </label>
              {/each}
            </div>
          </div>
        {/if}
        <label class="checkbox-inline"><input type="checkbox" bind:checked={editing.enabled} /> 启用该应用</label>
      </div>
      <div class="dialog-actions">
        <button type="button" class="button" onclick={() => editDialog.close()}>取消</button>
        <button type="submit" class="button primary" disabled={busy}>保存配置</button>
      </div>
    </form>
  {/if}
</dialog>
