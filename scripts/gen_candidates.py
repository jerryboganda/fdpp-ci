#!/usr/bin/env python3
"""Generate password candidates and the T-SQL batches that try them.

Outputs:
  candidates_all.txt  - every candidate, one per line (for the offline cracker)
  cands_calib.sql     - T-SQL batch trying all candidates against the
                        calibration backup (self-test; must find pw1)
  cands_user.sql      - same batch against the user's backup
"""
import argparse

BASES = [
    'admin', 'sa', 'password', 'root', 'user', 'master', 'manager', 'dba',
    'test', 'demo', 'welcome', 'qwerty', 'secret', 'changeme', 'abc123',
    'letmein', '1qaz2wsx', 'asdfgh', 'a123456', '123qwe', 'qwe123',
    'pakistan', 'lahore', 'karachi', 'islamabad', 'punjab', 'multan',
    'faisalabad', 'sialkot', 'gujranwala', 'rawalpindi', 'peshawar', 'quetta',
    'fazal', 'fazaldin', 'fazal din', 'din', 'fdpp', 'pp19', 'pp19v3',
    'pharmacy', 'pharma', 'medical', 'medicine', 'chemist', 'drug', 'store',
    'shop', 'pos', 'retail', 'sale', 'sales', 'invoice', 'stock', 'inventory',
    'customer', 'hospital', 'clinic', 'doctor', 'patient',
    'bismillah', 'allah', 'mashallah', 'inshallah', 'islam', 'muhammad',
    'ahmed', 'ali', 'usman', 'khan', 'malik', 'iqra', 'hafiz', '786',
]
SUF_CORE = [
    '', '1', '2', '3', '12', '123', '1234', '12345', '123456',
    '!', '@', '#', '1!', '123!', '123@', '123#', '@123', '#123', '!123',
    '_123', '786', '786786', '2017', '2018', '2019', '2020', '2021', '2022',
    '2023', '2024', '2025', '2026', '19', '20', '@2019', '!2019', '#2019',
]
SUF_ALL = SUF_CORE + [
    '1234567', '12345678', '123456789', '1234567890', '$', '!!', '@#',
    '_', '007', '110', '5150', '99', '88', '69', '92', '0300', 'v1', 'v2',
    'v3', 'V3', 'new', 'old', 'ok', 'go', '2016', '@1234', '!234', '19!',
    '20!', '2019!', '2020!', '2021!', '2022!',
]
PRE_ALL = ['', '1', '! ', '@', '#', '786', '92', 'the', 'my']
EXTRA = [
    'P@ssw0rd', 'p@ssw0rd', 'Passw0rd', 'passw0rd', 'Password1', 'password1',
    'Password!', 'password!', 'P@ssword1', 'Passw0rd!', 'Adm1n', 'adm1n',
    'sa2008', 'sa2005', 'sa2012', 'sql2008', 'sql2005', 'sql2012',
    'sqlserver', 'SQLserver', '1q2w3e4r', 'zaq12wsx', 'zxcvbn', 'asd123',
    'zxc123', 'FazalDin@123', 'fazaldin@123', 'FDPP@123', 'PP19@123',
    'Pharmacy@123', 'Admin@123', 'admin@123', 'SA@123', 'sa@123',
]


def expand(prefixes):
    out = set()
    for b in BASES:
        for form in (b.lower(), b.capitalize(), b.upper()):
            for p in prefixes:
                for s in SUF_ALL:
                    out.add(p + form + s)
    out.update(EXTRA)
    return sorted(w for w in out if w and "'" not in w and len(w) <= 100)


def write_sql(path, bakpath, words):
    vals = "),(".join("N'" + w.replace("'", "''") + "'" for w in words)
    sql = f"""SET NOCOUNT ON;
CREATE TABLE #cands (pw nvarchar(128));
INSERT INTO #cands VALUES ({vals});
CREATE TABLE #ok (mode nvarchar(20), pw nvarchar(128));
DECLARE @pw nvarchar(128), @sql nvarchar(400);
DECLARE cur CURSOR LOCAL FAST_FORWARD FOR SELECT pw FROM #cands;
OPEN cur
FETCH NEXT FROM cur INTO @pw
WHILE @@FETCH_STATUS = 0
BEGIN
  SET @sql = N'RESTORE HEADERONLY FROM DISK = N''{bakpath}'' WITH PASSWORD = N''' + REPLACE(@pw, N'''', N'''''') + N'''';
  BEGIN TRY
    EXEC(@sql);
    IF NOT EXISTS (SELECT 1 FROM #ok WHERE mode = N'password' AND pw = @pw) INSERT #ok VALUES (N'password', @pw);
  END TRY BEGIN CATCH END CATCH;
  SET @sql = N'RESTORE HEADERONLY FROM DISK = N''{bakpath}'' WITH MEDIAPASSWORD = N''' + REPLACE(@pw, N'''', N'''''') + N'''';
  BEGIN TRY
    EXEC(@sql);
    IF NOT EXISTS (SELECT 1 FROM #ok WHERE mode = N'mediapassword' AND pw = @pw) INSERT #ok VALUES (N'mediapassword', @pw);
  END TRY BEGIN CATCH END CATCH;
  FETCH NEXT FROM cur INTO @pw
END
CLOSE cur
DEALLOCATE cur
SELECT mode, pw FROM #ok;
"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(sql)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out-all', default='candidates_all.txt')
    ap.add_argument('--sql-calib', default='cands_calib.sql')
    ap.add_argument('--sql-user', default='cands_user.sql')
    ap.add_argument('--bak-user-path',
                    default='/bakshare/FazalDinPP19V3DBDump.BAK')
    ap.add_argument('--bak-calib-path',
                    default='/bakshare/calib1.bak')
    a = ap.parse_args()

    core = expand([''])
    alled = expand(PRE_ALL)
    with open(a.out_all, 'w', encoding='utf-8') as f:
        f.write('\n'.join(alled) + '\n')
    write_sql(a.sql_calib, a.bak_calib_path, ['ZzTestPass01'] + core)
    write_sql(a.sql_user, a.bak_user_path, core)
    print(f"core candidates: {len(core)}, all candidates: {len(alled)}")


if __name__ == '__main__':
    main()
