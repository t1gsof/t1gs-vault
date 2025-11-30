const getCsrfToken = () => document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

async function fetchSecure(url, options = {}) {
    const headers = { 'CSRF-Token': getCsrfToken(), 'Content-Type': 'application/json', ...options.headers };
    const res = await fetch(url, { ...options, headers });
    if (res.status === 403) return window.location.reload();
    return res;
}

let allItems = []; 
let currentCategory = 'all'; 
let searchQuery = ''; 
let editModeId = null; 

document.addEventListener('DOMContentLoaded', () => {
    const addBtn = document.getElementById('addBtn');
    const closePanelBtn = document.getElementById('closePanelBtn');
    const addPanel = document.getElementById('addPanel');
    const panelTitle = document.getElementById('panelTitle');
    const saveBtn = document.getElementById('saveBtn');
    const searchInput = document.getElementById('searchInput');
    const stealthToggle = document.getElementById('stealth_mode_toggle');

    if (stealthToggle) {
        const isStealth = localStorage.getItem('stealthMode') === 'true';
        stealthToggle.checked = isStealth;
        if(isStealth) document.body.classList.add('stealth-active');

        stealthToggle.addEventListener('change', (e) => {
            if(e.target.checked) {
                document.body.classList.add('stealth-active');
                localStorage.setItem('stealthMode', 'true');
            } else {
                document.body.classList.remove('stealth-active');
                localStorage.setItem('stealthMode', 'false');
            }
        });
    }

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            searchQuery = e.target.value.toLowerCase();
            renderVault(); 
        });
    }

    if (addBtn) {
        addBtn.addEventListener('click', () => {
            resetForm();
            editModeId = null;
            panelTitle.innerHTML = `<div class="w-1.5 h-1.5 rounded-full bg-violet-500"></div> Add New Item`;
            saveBtn.textContent = 'Save Item';
            addPanel.classList.remove('hidden');
        });
    }

    if (closePanelBtn) closePanelBtn.addEventListener('click', () => addPanel.classList.add('hidden'));

    document.querySelectorAll('.nav-category').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.nav-category').forEach(b => {
                b.classList.remove('bg-violet-600/10', 'text-violet-400', 'border-violet-600/10');
                b.classList.add('text-slate-400', 'border-transparent');
            });
            const target = e.currentTarget;
            target.classList.remove('text-slate-400', 'border-transparent');
            target.classList.add('bg-violet-600/10', 'text-violet-400', 'border-violet-600/10');

            currentCategory = target.dataset.category;
            renderVault(); 
        });
    });

    loadVault();

    const addForm = document.getElementById('addForm');
    if (addForm) {
        addForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const data = {
                category: document.getElementById('catInput').value,
                url: document.getElementById('url').value,
                username: document.getElementById('uName').value,
                password: document.getElementById('pwd').value
            };

            let url = '/api/vault';
            let method = 'POST';

            if (editModeId) {
                url = `/api/vault/${editModeId}`;
                method = 'PUT'; 
            }

            const res = await fetchSecure(url, { method, body: JSON.stringify(data) });

            if (res && res.ok) {
                addPanel.classList.add('hidden');
                loadVault();
            }
        });
    }
});

function resetForm() {
    document.getElementById('addForm').reset();
    document.getElementById('pwd').required = true; 
}

async function loadVault() {
    const res = await fetchSecure('/api/vault');
    if (!res || !res.ok) return;
    const data = await res.json();
    
    if (document.getElementById('userWelcome') && data.user) {
        document.getElementById('userWelcome').textContent = data.user;
    }
    
    allItems = data.items || [];
    renderVault();
}

function renderVault() {
    const list = document.getElementById('vaultList');
    list.innerHTML = '';

    const filtered = allItems.filter(item => {
        const categoryMatch = currentCategory === 'all' || item.category === currentCategory;
        const searchMatch = !searchQuery || 
                            (item.url && item.url.toLowerCase().includes(searchQuery)) ||
                            (item.username && item.username.toLowerCase().includes(searchQuery));
        return categoryMatch && searchMatch;
    });

    if (filtered.length === 0) {
        const message = searchQuery ? 'No items found for your search.' : 'No items in this category.';
        list.innerHTML = `<div class="text-slate-500 text-center py-10">${message}</div>`;
        return;
    }

    filtered.forEach(item => {
        const el = document.createElement('div');
        el.className = 'glass-panel rounded-xl p-4 mb-3 hover:bg-violet-900/10 transition-all group border border-slate-800 hover:border-violet-500/30';
        el.innerHTML = `
            <div class="flex items-center justify-between cursor-pointer header-click">
                <div class="flex items-center gap-4">
                    <div class="w-10 h-10 rounded-full bg-violet-500/10 flex items-center justify-center text-violet-400">
                        ${getIcon(item.category)}
                    </div>
                    <div>
                        <div class="font-medium text-slate-200 sensitive-data">${escapeHtml(item.url)}</div>
                        <div class="text-sm text-slate-500 sensitive-data">${escapeHtml(item.username)}</div>
                    </div>
                </div>
                <div class="text-slate-600 group-hover:text-violet-400 transition-colors">▼</div>
            </div>
            
            <div class="hidden mt-4 pt-4 border-t border-slate-700/50 details-body">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="text-xs text-slate-500 uppercase tracking-wider">Username</label>
                        <div class="text-slate-300 font-mono mt-1 select-all sensitive-data">${escapeHtml(item.username)}</div>
                    </div>
                    <div>
                        <label class="text-xs text-slate-500 uppercase tracking-wider">Password</label>
                        <div class="flex items-center gap-2 mt-1">
                            <code class="bg-black/30 px-2 py-1 rounded text-violet-300 font-mono text-sm password-display">••••••••••••</code>
                            <button class="text-xs text-violet-400 hover:text-violet-300 btn-reveal font-bold" data-id="${item.id}">Reveal</button>
                            <button class="text-xs text-slate-400 hover:text-white btn-copy" data-id="${item.id}">Copy</button>
                        </div>
                    </div>
                </div>
                <div class="mt-4 flex justify-end gap-3">
                    <button class="btn-edit text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 hover:bg-blue-500/10 px-2 py-1 rounded transition-all" data-id="${item.id}">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                        Edit
                    </button>
                    <button class="btn-delete text-xs text-red-400 hover:text-red-300 flex items-center gap-1 hover:bg-red-500/10 px-2 py-1 rounded transition-all" data-id="${item.id}">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                        Delete
                    </button>
                </div>
            </div>
        `;

        el.querySelector('.header-click').addEventListener('click', () => el.querySelector('.details-body').classList.toggle('hidden'));

        el.querySelector('.btn-reveal').addEventListener('click', async (e) => {
            const btn = e.target;
            const display = el.querySelector('.password-display');
            if (btn.textContent === 'Hide') {
                display.textContent = '••••••••••••';
                btn.textContent = 'Reveal';
                return;
            }
            const res = await fetchSecure(`/api/vault/${btn.dataset.id}/password`);
            if(res && res.ok) {
                const json = await res.json();
                display.textContent = json.password;
                btn.textContent = 'Hide';
            }
        });

        el.querySelector('.btn-copy').addEventListener('click', async (e) => {
            const res = await fetchSecure(`/api/vault/${e.target.dataset.id}/password`);
            if(res && res.ok) {
                const json = await res.json();
                navigator.clipboard.writeText(json.password);
                e.target.textContent = 'Copied!';
                setTimeout(() => e.target.textContent = 'Copy', 1500);
            }
        });

        el.querySelector('.btn-delete').addEventListener('click', async (e) => {
            if(!confirm('Delete this item?')) return;
            const res = await fetchSecure(`/api/vault/${e.target.dataset.id}`, { method: 'DELETE' });
            if(res && res.ok) loadVault();
        });

        el.querySelector('.btn-edit').addEventListener('click', (e) => {
            const id = e.target.dataset.id; 
            const itemToEdit = allItems.find(i => i.id == id); 

            if(itemToEdit) {
                document.getElementById('url').value = itemToEdit.url;
                document.getElementById('uName').value = itemToEdit.username;
                document.getElementById('catInput').value = itemToEdit.category || 'web';
                document.getElementById('pwd').value = ''; 
                document.getElementById('pwd').placeholder = '(Unchanged) Enter new to update';
                document.getElementById('pwd').required = false; 

                document.getElementById('panelTitle').innerHTML = `<div class="w-1.5 h-1.5 rounded-full bg-blue-500"></div> Edit Item`;
                document.getElementById('saveBtn').textContent = 'Update Item';
                
                editModeId = id; 
                document.getElementById('addPanel').classList.remove('hidden');
            }
        });

        list.appendChild(el);
    });
}

function getIcon(cat) {
    if(cat === 'card') return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="22" height="14" x="1" y="4" rx="2" ry="2"/><line x1="1" x2="23" y1="10" y2="10"/></svg>`;
    if(cat === 'email') return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>`;
    if(cat === 'social') return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"/></svg>`;
    if(cat === 'wifi') return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" x2="12.01" y1="20" y2="20"/></svg>`;
    if(cat === 'bank') return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18"/><path d="M5 21v-7"/><path d="M19 21v-7"/><path d="M4 10a5 5 0 0 1 16 0"/><path d="M12 14v7"/></svg>`;
    if(cat === 'id') return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`;
    if(cat === 'note') return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`;
    return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`;
}

function escapeHtml(text) {
    if (!text) return text;
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}