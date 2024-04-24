# Parse the dmarc report.
# extract information when DKIM or SPF policy evaluation  is "fail".

# Used module
Install-Module PSCompression -Scope CurrentUser

#region environment variables

# directory for dmarc report files
$ORIGIN_DIR  = ".\original_files"

# output file
$OUTPUT_FILE = ".\fail_list.csv"
#endregion

#region function

# null to empty string
$n2s = {
    param ($v)
    return $v ? $v : [string]::Empty
}

# IP Address to Dns Name
$dnsCache = @{}
$i2d = {
    param ($v)
    if ([string]::IsNullOrWhiteSpace($v)) {
        return [string]::Empty
    }
    try {
        if ($dnsCache.Contains($v)) {
            return $dnsCache[$v]
        }
        $r = Resolve-DnsName -Name $v
        $dnsCache[$v] = $r.NameHost
        return $r.NameHost    
    } catch {
        Write-Host $Error
        $dnsCache[$v] = [string]::Empty
        return $dnsCache[$v]
    }
}
#endregion

#region process
Write-Host "$(Get-Date) Process Start"

# clear error collection
$Error.Clear()

# get dmarc file list
$dmarc_files = (Get-ChildItem -Path $ORIGIN_DIR)
Write-Host -NoNewline ("Traget file count: $($dmarc_files.Length)")

# results variable
$results = @()

# repeat for dmarc files
$dmarc_files | ForEach-Object { $i = 0 } {
    Write-Host -NoNewline ("`rTraget file count: $((++$i))/$($dmarc_files.Length)")

    $file = $_

    # unzip dmarc file
    $xml = $null
    switch ($file.Extension) {
        '.gz' {
            $xml = [xml](Expand-GzipArchive -Path $file.FullName)
        }
        '.zip' {
            $xml = [xml](Get-ZipEntry $file.FullName -Include *.xml | Get-ZipEntryContent -Raw)
        }
        Default {
            Write-Warning ('Unknown Extention, File name: {0}')
            return
        }
    }

    # get dmarc metadata
    [string]$org_name   = $n2s.Invoke($xml.feedback.report_metadata.org_name)
    [string]$report_id  = $n2s.Invoke($xml.feedback.report_metadata.report_id)
    [string]$begin_date = $n2s.Invoke($xml.feedback.report_metadata.date_range.begin)
    [string]$end_date   = $n2s.Invoke($xml.feedback.report_metadata.date_range.end)

    $xml.feedback.record | %{
        $record = $_
        # policy evaluated
        [string]$policy_evaluated_dkim        = $n2s.Invoke($record.row.policy_evaluated.dkim)
        [string]$policy_evaluated_spf         = $n2s.Invoke($record.row.policy_evaluated.spf)
        [string]$policy_evaluated_disposition = $n2s.Invoke($record.row.policy_evaluated.disposition)
        # auth_results
        [string]$auth_results_dkim            = $n2s.Invoke($record.auth_results.dkim.result)
        [string]$auth_results_spf             = $n2s.Invoke($record.auth_results.spf.result)
        # source_ip and DNS name from source_ip
        [string]$source_ip                    = $n2s.Invoke($record.row.source_ip)
        [string]$source_dnsname               = $i2d.Invoke($record.row.source_ip)
        # count
        [string]$count                        = $n2s.Invoke($record.row.count)
        # header From
        [string]$header_from                  = $n2s.Invoke($record.identifiers.header_from)
        # envelope From
        [string]$envelope_from                = $n2s.Invoke($record.identifiers.envelope_from)
        # dmarc file name
        [string]$filename                     = $n2s.Invoke($file.Name)

        # skip when DKIM, SPF policy evaluation is "pass"
        if ($policy_evaluated_dkim -eq 'pass' -and $policy_evaluated_spf -eq 'pass') {
            return
        }

        # DKIM or SPF policy evaluation is "fail"
        $results += [ordered]@{
            'org_name'                     = $org_name
            'report_id'                    = $report_id
            'policy_evaluated_dkim'        = $policy_evaluated_dkim
            'policy_evaluated_spf'         = $policy_evaluated_spf
            'policy_evaluated_disposition' = $policy_evaluated_disposition
            'auth_results_dkim'            = $auth_results_dkim
            'auth_results_spf'             = $auth_results_spf
            'begin_date'                   = $(Get-Date -UnixTimeSeconds $begin_date)
            'end_date'                     = $(Get-Date -UnixTimeSeconds $end_date)
            'source_ip'                    = $source_ip
            'source_dnsname'               = $source_dnsname
            'count'                        = $count
            'header_from'                  = $header_from
            'envelope_from'                = $envelope_from
            'filename'                     = $filename
        }
    }
}

Write-Host "`n$(Get-Date) Process End"
#endregion

# result to CSV file
$results | ConvertTo-Csv > $OUTPUT_FILE
Write-Host "$(Get-Date) output file => $OUTPUT_FILE"
