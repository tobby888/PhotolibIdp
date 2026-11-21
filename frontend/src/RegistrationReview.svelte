<script>
  import { onMount } from 'svelte'
  import { api, date } from './api.js'

  let { onExpired } = $props()
  let items = $state([])
  let statusFilter = $state('PENDING')
  let keyword = $state('')
  let loading = $state(true)
  let error = $state('')
  let feedback = $state('')
  let busy = $state(false)

  const statusLabels = { PENDING: '待审核', APPROVED: '已通过', REJECTED: '已驳回' }

  async function reload() {
    loading = true
    error = ''
    try {
      const params = new URLSearchParams()
      if (statusFilter) params.set('status', statusFilter)
      if (keyword.trim()) params.set('keyword', keyword.trim())
      const qs = params.toString() ? `?${params.toString()}` : ''
      items = await api('/api/v1/registration-applications' + qs)
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      loading = false
    }
  }

  onMount(() => { void reload() })

  async function approve(ids) {
    if (busy || !ids.length) return
    busy = true
    error = ''
    try {
      const res = await api('/api/v1/registration-applications/approve', {
        method: 'POST',
        body: { ids },
      })
      if (res.failed?.length) {
        error = res.failed.map(f => `${f.username || f.id}: ${f.message}`).join('；')
      }
      if (res.succeeded?.length) {
        feedback = `已通过 ${res.succeeded.length} 份注册申请，账号已正式创建。`
      }
      await reload()
    } catch (err) {
      if (err.status === 401) onExpired()
      else error = err.message
    } finally {
      busy = false
    }
  }

  async function reject(item) {
    if (busy) return
    const reason = prompt(`驳回 ${item.displayName} (@${item.username}) 的注册申请，可选填写原因：`, '')
    if (reason === null) return
    busy = true
    error = ''
    try {
      const res = await api('/api/v1/registration-applications/reject', {
        method: 'POST',
        body: { ids: [item.id], reason },
      })
      if (res.failed?.length) {
        error = res.failed.map(f => f.message).join('；')
      } else {
        feedback = `已驳回 @${item.username} 的注册申请并归还注册码名额。`
      }
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
      <h2>注册申请审核</h2>
      <p class="muted">审核通过后自动创建统一认证账号，驳回将自动归还注册码占用名额。</p>
    </div>
    <div class="login-actions">
      <select class="toolbar-input" style="min-width:120px" bind:value={statusFilter} onchange={reload}>
        <option value="PENDING">待审核</option>
        <option value="APPROVED">已通过</option>
        <option value="REJECTED">已驳回</option>
        <option value="">全部状态</option>
      </select>
      <input class="toolbar-input" placeholder="搜索姓名、账号或邮箱" bind:value={keyword} onkeydown={e => e.key === 'Enter' && reload()} />
      <button class="button" onclick={reload} disabled={loading}>查询</button>
    </div>
  </div>
  {#if loading && !items.length}
    <p class="empty">正在读取注册申请…</p>
  {:else if !items.length}
    <p class="empty">当前筛选条件下没有注册申请。</p>
  {/if}
  {#each items as item (item.id)}
    <div class="row">
      <div class="row-content">
        <div class="row-title">
          <strong>{item.displayName}</strong>
          <code>@{item.username}</code>
          <span class={'status ' + (item.status === 'APPROVED' ? 'succeeded' : item.status === 'REJECTED' ? 'failed' : 'running')}>
            {statusLabels[item.status] || item.status}
          </span>
        </div>
        <div class="metadata">
          <span>邮箱: {item.email}</span>
          <span>注册码: {item.codeName || `#${item.codeId}`}</span>
          <span>提交于 {date(item.createdAt)}</span>
          {#if item.reviewedAt}<span>审核于 {date(item.reviewedAt)}（{item.reviewerName || '管理员'}）</span>{/if}
          {#if item.rejectReason}<span>驳回原因: {item.rejectReason}</span>{/if}
        </div>
      </div>
      {#if item.status === 'PENDING'}
        <div class="login-actions">
          <button class="button compact primary" disabled={busy} onclick={() => approve([item.id])}>通过并建号</button>
          <button class="button compact destructive" disabled={busy} onclick={() => reject(item)}>驳回</button>
        </div>
      {/if}
    </div>
  {/each}
</section>
