<script>
  import { onMount } from 'svelte'
  import { api, date } from './api.js'

  let { currentUser, onExpired } = $props()
  let users = $state([])
  let keyword = $state('')
  let loading = $state(true)
  let error = $state('')
  let feedback = $state('')
  let createdPassword = $state(null)
  let busy = $state(false)

  let createDialog
  let editDialog
  let editing = $state(null)

  async function reload() {
    loading = true
    error = ''
    try {
      const q = keyword.trim() ? `?keyword=${encodeURIComponent(keyword.trim())}` : ''
      users = await api('/api/v1/users' + q)
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      loading = false
    }
  }

  onMount(() => { void reload() })

  async function createUser(event) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const data = Object.fromEntries(new FormData(form))
    busy = true
    error = ''
    try {
      const result = await api('/api/v1/users', {
        method: 'POST',
        body: {
          username: data.username,
          displayName: data.displayName,
          email: data.email || '',
          phone: data.phone || '',
          wecomUserid: data.wecomUserid || '',
          admin: data.admin === 'on',
        },
      })
      form.reset()
      createDialog.close()
      createdPassword = { username: result.user.username, displayName: result.user.displayName, password: result.initialPassword }
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  function openEdit(user) {
    editing = { ...user }
    editDialog.showModal()
  }

  async function saveEdit(event) {
    event.preventDefault()
    if (busy || !editing) return
    busy = true
    error = ''
    try {
      await api(`/api/v1/users/${editing.id}`, {
        method: 'PUT',
        body: {
          username: editing.username,
          displayName: editing.displayName,
          email: editing.email || '',
          phone: editing.phone || '',
          wecomUserid: editing.wecomUserid || '',
          admin: Boolean(editing.admin),
          enabled: Boolean(editing.enabled),
          version: editing.version,
        },
      })
      editDialog.close()
      feedback = `已更新账号 @${editing.username}`
      editing = null
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  async function toggleEnabled(user) {
    if (busy) return
    busy = true
    error = ''
    try {
      const action = user.enabled ? 'disable' : 'enable'
      await api(`/api/v1/users/${user.id}/${action}`, { method: 'POST' })
      feedback = `已${user.enabled ? '停用' : '启用'}账号 @${user.username}`
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  async function resetPassword(user) {
    if (busy || !confirm(`确定重置 ${user.displayName} (@${user.username}) 的登录密码吗？`)) return
    busy = true
    error = ''
    try {
      const res = await api(`/api/v1/users/${user.id}/password`, { method: 'PUT' })
      createdPassword = { username: user.username, displayName: user.displayName, password: res.initialPassword }
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  async function removeUser(user) {
    if (busy || !confirm(`确定删除账号 ${user.displayName} (@${user.username}) 吗？`)) return
    busy = true
    error = ''
    try {
      await api(`/api/v1/users/${user.id}`, { method: 'DELETE' })
      feedback = `已删除账号 @${user.username}`
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
{#if createdPassword}
  <div class="secret-box" role="status">
    <strong>账号 {createdPassword.displayName} (@{createdPassword.username}) 的一次性初始密码：</strong>
    <p><code>{createdPassword.password}</code>（请通过安全渠道交给用户，首次登录后须强制修改密码）</p>
    <button class="button compact" onclick={() => createdPassword = null}>我已保存</button>
  </div>
{/if}

<section class="panel">
  <div class="panel-heading">
    <div>
      <h2>成员账号目录</h2>
      <p class="muted">在统一认证中心集中创建、启停、重置密码与删除所有成员账号。</p>
    </div>
    <div class="login-actions">
      <input class="toolbar-input" placeholder="搜索姓名、账号或邮箱" bind:value={keyword} onkeydown={e => e.key === 'Enter' && reload()} />
      <button class="button" onclick={reload} disabled={loading}>查询</button>
      <button class="button primary" onclick={() => createDialog.showModal()}>创建账号</button>
    </div>
  </div>
  {#if loading && !users.length}
    <p class="empty">正在读取账号列表…</p>
  {:else if !users.length}
    <p class="empty">没有匹配的成员账号。</p>
  {/if}
  {#each users as item (item.id)}
    <div class="row">
      <div class="row-content">
        <div class="row-title">
          <strong>{item.displayName}</strong>
          <code>@{item.username}</code>
          <span class={'status ' + (item.enabled ? 'succeeded' : 'failed')}>{item.enabled ? '正常' : '已停用'}</span>
          {#if item.admin}<span class="status running">系统管理员</span>{/if}
          {#if item.mustChangePassword}<span class="status">待改初始密码</span>{/if}
        </div>
        <div class="metadata">
          <span>ID: <code>{item.id}</code></span>
          {#if item.email}<span>邮箱: {item.email}</span>{/if}
          {#if item.phone}<span>手机: {item.phone}</span>{/if}
          {#if item.wecomUserid}<span>企微: <code>{item.wecomUserid}</code></span>{/if}
          <span>创建于 {date(item.createdAt)}</span>
        </div>
      </div>
      <div class="login-actions">
        <button class="button compact" disabled={busy} onclick={() => openEdit(item)}>修改</button>
        <button class="button compact" disabled={busy} onclick={() => toggleEnabled(item)}>{item.enabled ? '停用' : '启用'}</button>
        <button class="button compact" disabled={busy} onclick={() => resetPassword(item)}>重置密码</button>
        {#if item.id !== currentUser?.id}
          <button class="button compact destructive" disabled={busy} onclick={() => removeUser(item)}>删除</button>
        {/if}
      </div>
    </div>
  {/each}
</section>

<dialog bind:this={createDialog}>
  <form onsubmit={createUser}>
    <h2>创建成员账号</h2>
    <div class="form-stack">
      <label>登录账号 <input name="username" required pattern="[A-Za-z0-9_.-]{3,64}" placeholder="3-64 位字母、数字或 ._-" /></label>
      <label>显示姓名 <input name="displayName" required maxlength="100" placeholder="成员真实姓名" /></label>
      <label>邮箱（可选，可用于邮箱登录） <input name="email" type="email" maxlength="255" placeholder="name@example.com" /></label>
      <label>手机号（可选） <input name="phone" maxlength="32" /></label>
      <label>企业微信 UserID（可选） <input name="wecomUserid" maxlength="64" placeholder="例如 ZhangSan" /></label>
      <label class="checkbox-inline"><input type="checkbox" name="admin" /> 授予统一认证中心管理员权限</label>
    </div>
    <div class="dialog-actions">
      <button type="button" class="button" onclick={() => createDialog.close()}>取消</button>
      <button type="submit" class="button primary" disabled={busy}>创建账号</button>
    </div>
  </form>
</dialog>

<dialog bind:this={editDialog}>
  {#if editing}
    <form onsubmit={saveEdit}>
      <h2>修改账号 · {editing.displayName}</h2>
      <div class="form-stack">
        <label>登录账号 <input bind:value={editing.username} required pattern="[A-Za-z0-9_.-]{3,64}" /></label>
        <label>显示姓名 <input bind:value={editing.displayName} required maxlength="100" /></label>
        <label>邮箱 <input bind:value={editing.email} type="email" maxlength="255" /></label>
        <label>手机号 <input bind:value={editing.phone} maxlength="32" /></label>
        <label>企业微信 UserID <input bind:value={editing.wecomUserid} maxlength="64" /></label>
        <label class="checkbox-inline"><input type="checkbox" bind:checked={editing.admin} /> 统一认证中心管理员</label>
        <label class="checkbox-inline"><input type="checkbox" bind:checked={editing.enabled} /> 账号启用</label>
      </div>
      <div class="dialog-actions">
        <button type="button" class="button" onclick={() => editDialog.close()}>取消</button>
        <button type="submit" class="button primary" disabled={busy}>保存</button>
      </div>
    </form>
  {/if}
</dialog>
