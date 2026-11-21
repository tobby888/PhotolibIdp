<script>
  import { onMount } from 'svelte'
  import { api, date } from './api.js'

  let { onExpired } = $props()
  let codes = $state([])
  let apps = $state([])
  let keyword = $state('')
  let loading = $state(true)
  let error = $state('')
  let feedback = $state('')
  let busy = $state(false)

  let createDialog
  let selectedApps = $state([])

  const statusLabels = {
    ACTIVE: '生效中',
    NOT_STARTED: '未开始',
    EXPIRED: '已过期',
    EXHAUSTED: '已满额',
    DISABLED: '已停用',
  }

  function defaultUntil() {
    const d = new Date(Date.now() + 7 * 86400_000)
    return d.toISOString().slice(0, 16)
  }

  async function reload() {
    loading = true
    error = ''
    try {
      const q = keyword.trim() ? `?keyword=${encodeURIComponent(keyword.trim())}` : ''
      const [codeList, appList] = await Promise.all([api('/api/v1/registration-codes' + q), api('/api/v1/apps')])
      codes = codeList
      apps = appList
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      loading = false
    }
  }

  onMount(() => { void reload() })

  function toggleApp(id) {
    selectedApps = selectedApps.includes(id) ? selectedApps.filter(x => x !== id) : [...selectedApps, id]
  }

  async function createCode(event) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const data = Object.fromEntries(new FormData(form))
    busy = true
    error = ''
    try {
      const res = await api('/api/v1/registration-codes', {
        method: 'POST',
        body: {
          name: data.name,
          maxUses: Number(data.maxUses),
          validUntil: new Date(data.validUntil).toISOString(),
          allowedAppIds: selectedApps,
        },
      })
      form.reset()
      selectedApps = []
      createDialog.close()
      feedback = `已生成注册码 ${res.code}（${res.name}）`
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  async function toggleCode(code) {
    if (busy) return
    busy = true
    error = ''
    try {
      await api(`/api/v1/registration-codes/${code.id}`, {
        method: 'PUT',
        body: {
          name: code.name,
          maxUses: code.maxUses,
          validFrom: code.validFrom,
          validUntil: code.validUntil,
          allowedAppIds: code.allowedAppIds,
          enabled: !code.enabled,
          version: code.version,
        },
      })
      feedback = `已${code.enabled ? '停用' : '启用'}注册码 ${code.code}`
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  async function removeCode(code) {
    if (busy || !confirm(`确定删除注册码「${code.name}」(${code.code}) 吗？`)) return
    busy = true
    error = ''
    try {
      await api(`/api/v1/registration-codes/${code.id}`, { method: 'DELETE' })
      feedback = `已删除注册码 ${code.code}`
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

<section class="panel">
  <div class="panel-heading">
    <div>
      <h2>注册码管理</h2>
      <p class="muted">生成注册码发放给新成员自助申请账号，经管理员在「注册审核」通过后生效。</p>
    </div>
    <div class="login-actions">
      <input class="toolbar-input" placeholder="搜索名称或注册码" bind:value={keyword} onkeydown={e => e.key === 'Enter' && reload()} />
      <button class="button" onclick={reload} disabled={loading}>查询</button>
      <button class="button primary" onclick={() => createDialog.showModal()}>新建注册码</button>
    </div>
  </div>
  {#if loading && !codes.length}
    <p class="empty">正在读取注册码…</p>
  {:else if !codes.length}
    <p class="empty">暂无注册码。</p>
  {/if}
  {#each codes as item (item.id)}
    <div class="row">
      <div class="row-content">
        <div class="row-title">
          <strong>{item.name}</strong>
          <code>{item.code}</code>
          <span class={'status ' + (item.status === 'ACTIVE' ? 'succeeded' : 'failed')}>{statusLabels[item.status] || item.status}</span>
        </div>
        <div class="metadata">
          <span>名额: 已占用 {item.usedCount} / {item.maxUses}（其中待审核 {item.pendingCount}）</span>
          <span>有效期: {date(item.validFrom)} 至 {date(item.validUntil)}</span>
        </div>
      </div>
      <div class="login-actions">
        <button class="button compact" disabled={busy} onclick={() => toggleCode(item)}>{item.enabled ? '停用' : '启用'}</button>
        {#if item.usedCount === 0}
          <button class="button compact destructive" disabled={busy} onclick={() => removeCode(item)}>删除</button>
        {/if}
      </div>
    </div>
  {/each}
</section>

<dialog bind:this={createDialog}>
  <form onsubmit={createCode}>
    <h2>新建注册码</h2>
    <div class="form-stack">
      <label>名称（用途说明） <input name="name" required maxlength="100" placeholder="例如 2026 秋季招新" /></label>
      <label>可注册人数上限 <input name="maxUses" type="number" min="1" max="1000" value="30" required /></label>
      <label>截止时间 <input name="validUntil" type="datetime-local" value={defaultUntil()} required /></label>
      {#if apps.length}
        <div>
          <span style="font-size:.9rem;font-weight:600">审核通过后自动授予访问权的应用（可选）</span>
          <div class="user-checklist">
            {#each apps as app (app.id)}
              <label class="checkbox-inline">
                <input type="checkbox" checked={selectedApps.includes(app.id)} onchange={() => toggleApp(app.id)} />
                <span>{app.name} (<code>{app.clientId}</code>)</span>
              </label>
            {/each}
          </div>
        </div>
      {/if}
    </div>
    <div class="dialog-actions">
      <button type="button" class="button" onclick={() => createDialog.close()}>取消</button>
      <button type="submit" class="button primary" disabled={busy}>生成注册码</button>
    </div>
  </form>
</dialog>
