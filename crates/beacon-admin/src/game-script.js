        const loadLanes = async () => {
            const list = document.getElementById('lanes-list');
            try {
                const health = await api('/forwards/health');
                const metrics = await api('/forwards/metrics');
                const rows = health.data || [];
                const m = Object.fromEntries((metrics.data || []).map(x => [x.id, x]));
                list.replaceChildren();
                if (!rows.length) { appendText(list, 'empty', 'No lanes'); return; }
                for (const h of rows) {
                    const mm = m[h.id] || {};
                    const row = appendText(list, 'site-row', `${h.id} ${h.game_name} ${h.protocol} ${h.mode} ${h.state} ${mm.connections_total || 0} conns`);
                    appendButton(row, 'Delete', () => window.delLane(h.id));
                }
            } catch (e) { list.replaceChildren(); appendText(list, 'empty', 'Lanes: ' + e.message); }
        };
        window.delLane = async (id) => {
            if (!confirm('Delete lane ' + id + '?')) return;
            await api('/forwards/' + id, { method: 'DELETE' });
            loadLanes();
        };
        document.getElementById('lane-add-btn')?.addEventListener('click', async () => {
            const [th, tp] = (document.getElementById('lane-target').value || '').split(':');
            if (!document.getElementById('lane-id').value || !th || !tp) { alert('id + target host:port required'); return; }
            await api('/forwards', { method: 'POST', body: JSON.stringify({
                id: document.getElementById('lane-id').value,
                game_name: document.getElementById('lane-game').value || 'game',
                public_host: '',
                public_port: parseInt(document.getElementById('lane-port').value),
                protocol: document.getElementById('lane-proto').value,
                target_host: th, target_port: parseInt(tp),
                forward_mode: document.getElementById('lane-mode').value,
                owner: 'ui'
            })});
            loadLanes();
        });
        document.getElementById('lane-refresh-btn')?.addEventListener('click', loadLanes);


        loadLanes();
