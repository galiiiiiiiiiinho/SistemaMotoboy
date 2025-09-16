import re, calendar, io
import pandas as pd
from datetime import datetime
from pathlib import Path
from settings import PLANILHA_CAMINHO

def infer_month_year_from_filename(path: str):
    meses = {'JANEIRO':1,'FEVEREIRO':2,'MARÇO':3,'MARCO':3,'ABRIL':4,'MAIO':5,'JUNHO':6,'JULHO':7,'AGOSTO':8,'SETEMBRO':9,'OUTUBRO':10,'NOVEMBRO':11,'DEZEMBRO':12}
    stem = Path(path).stem.upper()
    m = re.search(r'(\d{4})', stem)
    year = int(m.group(1)) if m else datetime.now().year
    month = next((v for k,v in meses.items() if k in stem), datetime.now().month)
    return month, year

def first_nonempty_right(row_values, start_col, max_step=8):
    for j in range(start_col+1, min(len(row_values), start_col+1+max_step)):
        val = row_values[j]
        if pd.notna(val) and str(val).strip() != '':
            return val, j
    return None, None

def classify_period(headers_coords, col_index):
    if not headers_coords: return ''
    dists = {k: abs(col_index - c) for k,c in headers_coords.items()}
    return min(dists, key=dists.get)

def clamp_day(year, month, d):
    max_day = calendar.monthrange(year, month)[1]
    d = int(d)
    return min(max(d,1), max_day)

def extract_all(path: str):
    # Read workbook from BytesIO so the file isn't kept open/locked.
    month, year = infer_month_year_from_filename(path)

    with open(path, 'rb') as f:
        content = f.read()

    xls = pd.ExcelFile(io.BytesIO(content))
    sheets = [s for s in xls.sheet_names if s.isdigit() and len(s)==2]

    records = []
    for s in sheets:
        df = pd.read_excel(io.BytesIO(content), sheet_name=s, header=None)

        headers = {}
        for i in range(min(6, len(df))):
            for j, val in enumerate(df.iloc[i].tolist()):
                if isinstance(val, str):
                    v = val.upper()
                    if 'ROTA' in v and 'MANHÃ' in v: headers['Manhã'] = j
                    if 'ROTA' in v and 'TARDE' in v: headers['Tarde'] = j

        for i in range(len(df)):
            row = df.iloc[i].tolist()
            for j, val in enumerate(row):
                if isinstance(val, str) and 'EMPRESA' in val.upper():
                    periodo = classify_period(headers, j)

                    def get_field(label, offset):
                        r = i + offset
                        if r >= len(df): return ''
                        row_r = df.iloc[r].tolist()
                        base_c = None
                        for jj in range(j, min(j+3, len(row_r))):
                            cell = row_r[jj]
                            if isinstance(cell, str) and label in cell.upper():
                                base_c = jj; break
                        if base_c is None: return ''
                        valr, _ = first_nonempty_right(row_r, base_c, max_step=8)
                        return '' if valr is None else str(valr).strip()

                    empresa      = get_field('EMPRESA', 0)
                    pegar_com    = get_field('PEGAR',   1)
                    documento    = get_field('DOCUMENTO', 2)
                    solicitante  = get_field('SOLICITANTE', 3)
                    obs          = get_field('OBS', 5)

                    day = clamp_day(year, month, s)
                    records.append({
                        'Data': datetime(year, month, day).date(),
                        'Período': periodo or '',
                        'Empresa': empresa,
                        'PegarCom': pegar_com,
                        'Documento': documento,
                        'Solicitante': solicitante,
                        'Obs': obs
                    })

    df_all = pd.DataFrame.from_records(records)
    if df_all.empty: return df_all

    df_all = df_all[(df_all['Empresa'].astype(str).str.strip()!='') | (df_all['Documento'].astype(str).str.strip()!='')]
    order = {'Manhã':0, 'Tarde':1, '':2}
    df_all['__o'] = df_all['Período'].map(order).fillna(3)
    df_all = df_all.sort_values(['Data','__o']).drop(columns='__o')
    return df_all
