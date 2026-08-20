class SmartTable {
    constructor(containerId, options = {}) {
        this.containerId = containerId;
        this.safeId = containerId.replace(/-/g, '_');
        this.options = options;
        this.allData = [];
        this.filteredData = [];
        this.columns = [];
        this.visibleColumns = new Set();
        this.sortCol = null;
        this.sortDir = 'asc';
        this.filename = options.filename || 'export';
        this.title = options.title || 'Export';
    }

    setData(columns, data) {
        this.columns = columns;
        this.allData = data;
        this.visibleColumns = new Set(columns.map((_, i) => i));
        this.filteredData = [...data];
        this.render();
    }

    filter(term) {
        this.searchTerm = term.toLowerCase();
        this.filteredData = this.allData.filter(row =>
            row.some(cell => String(cell || '').toLowerCase().includes(this.searchTerm))
        );
        this.sort();
        this.renderBody();
        this.updateCount();
    }

    sort(colIdx) {
        if (colIdx !== undefined) {
            if (this.sortCol === colIdx) {
                this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                this.sortCol = colIdx;
                this.sortDir = 'asc';
            }
        }
        if (this.sortCol !== null) {
            this.filteredData.sort((a, b) => {
                const av = a[this.sortCol] || '';
                const bv = b[this.sortCol] || '';
                const an = parseFloat(av);
                const bn = parseFloat(bv);
                if (!isNaN(an) && !isNaN(bn)) {
                    return this.sortDir === 'asc' ? an - bn : bn - an;
                }
                return this.sortDir === 'asc'
                    ? String(av).localeCompare(String(bv))
                    : String(bv).localeCompare(String(av));
            });
        }
        this.renderBody();
        this.updateSortIndicators();
    }

    toggleColumn(idx) {
        if (this.visibleColumns.has(idx)) {
            if (this.visibleColumns.size > 1) this.visibleColumns.delete(idx);
        } else {
            this.visibleColumns.add(idx);
        }
        this.renderColPicker();
        this.renderHeader();
        this.renderBody();
    }

    render() {
        const container = document.getElementById(this.containerId);
        if (!container) return;
        const sid = this.safeId;
        container.innerHTML =
            '<div class="st-toolbar">' +
            '<div class="st-left">' +
            '<input type="text" class="st-search" placeholder="Search..." oninput="window.__st_' + sid + '.filter(this.value)">' +
            '<span class="st-count" id="st-count-' + sid + '"></span>' +
            '</div>' +
            '<div class="st-right">' +
            '<div class="st-col-picker-wrap">' +
            '<button class="st-btn st-btn-secondary" onclick="window.__st_' + sid + '.toggleColPicker()">Columns</button>' +
            '<div class="st-col-picker" id="st-cols-' + sid + '" style="display:none"></div>' +
            '</div>' +
            '<button class="st-btn st-btn-export" onclick="window.__st_' + sid + '.exportCSV()">CSV</button>' +
            '<button class="st-btn st-btn-export" onclick="window.__st_' + sid + '.exportExcel()">Excel</button>' +
            '</div>' +
            '</div>' +
            '<div class="st-table-wrap">' +
            '<table class="st-table">' +
            '<thead id="st-head-' + sid + '"></thead>' +
            '<tbody id="st-body-' + sid + '"></tbody>' +
            '</table>' +
            '</div>';

        window['__st_' + sid] = this;
        this.renderColPicker();
        this.renderHeader();
        this.renderBody();
        this.updateCount();
    }

    renderColPicker() {
        const picker = document.getElementById('st-cols-' + this.safeId);
        if (!picker) return;
        const sid = this.safeId;
        picker.innerHTML = this.columns.map((col, i) =>
            '<label class="st-col-item">' +
            '<input type="checkbox" ' + (this.visibleColumns.has(i) ? 'checked' : '') +
            ' onchange="window.__st_' + sid + '.toggleColumn(' + i + ')">' +
            col +
            '</label>'
        ).join('');
    }

    toggleColPicker() {
        const picker = document.getElementById('st-cols-' + this.safeId);
        if (picker) picker.style.display = picker.style.display === 'none' ? 'block' : 'none';
    }

    renderHeader() {
        const head = document.getElementById('st-head-' + this.safeId);
        if (!head) return;
        const sid = this.safeId;
        const cols = this.columns.map((col, i) => {
            if (!this.visibleColumns.has(i)) return '';
            return '<th onclick="window.__st_' + sid + '.sort(' + i + ')" id="st-th-' + sid + '-' + i + '">' +
                col + ' <span class="st-sort-icon">^v</span>' +
                '</th>';
        }).join('');
        head.innerHTML = '<tr>' + cols + '</tr>';
        this.updateSortIndicators();
    }

    renderBody() {
        const body = document.getElementById('st-body-' + this.safeId);
        if (!body) return;
        if (this.filteredData.length === 0) {
            body.innerHTML = '<tr><td colspan="' + this.visibleColumns.size + '" class="st-empty">No results found</td></tr>';
            return;
        }
        body.innerHTML = this.filteredData.map(row => {
            const cells = row.map((cell, i) => {
                if (!this.visibleColumns.has(i)) return '';
                const val = (cell === null || cell === undefined || cell === '') ? '<span class="na">N/A</span>' : cell;
                return '<td>' + val + '</td>';
            }).join('');
            return '<tr>' + cells + '</tr>';
        }).join('');
    }

    updateCount() {
        const el = document.getElementById('st-count-' + this.safeId);
        if (el) el.textContent = 'Showing ' + this.filteredData.length + ' of ' + this.allData.length;
    }

    updateSortIndicators() {
        this.columns.forEach((_, i) => {
            const th = document.getElementById('st-th-' + this.safeId + '-' + i);
            if (!th) return;
            const icon = th.querySelector('.st-sort-icon');
            if (!icon) return;
            if (i === this.sortCol) {
                icon.textContent = this.sortDir === 'asc' ? ' [A]' : ' [Z]';
                icon.style.color = '#0f9b8e';
            } else {
                icon.textContent = '^v';
                icon.style.color = '#555555';
            }
        });
    }

    getExportData() {
        const visibleIdxs = [...this.visibleColumns].sort((a, b) => a - b);
        const visibleCols = visibleIdxs.map(i => this.columns[i]);
        const rows = this.filteredData.map(row =>
            visibleIdxs.map(i => {
                const val = row[i];
                if (typeof val === 'string') return val.replace(/<[^>]+>/g, '').trim();
                return val;
            })
        );
        return { columns: visibleCols, rows };
    }

    async exportCSV() {
        const { columns, rows } = this.getExportData();
        const res = await fetch('/api/export/csv', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ columns, rows, filename: this.filename })
        });
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = this.filename + '.csv';
        a.click();
        URL.revokeObjectURL(url);
    }

    async exportExcel() {
        const { columns, rows } = this.getExportData();
        const res = await fetch('/api/export/excel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ columns, rows, filename: this.filename, title: this.title })
        });
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = this.filename + '.xlsx';
        a.click();
        URL.revokeObjectURL(url);
    }
}
