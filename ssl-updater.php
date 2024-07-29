#!/usr/bin/env php
<?php
class YcSsl {

    protected $ycBin = 'yc';
    protected $sslDir = '/etc/nginx/ssl';

    //script-name instanceId1:domain1 instanceId2:domain2
    public function handle(array $argv): void
    {
        $instances = array_slice($argv, 1);
        $instances = $this->normalizeInstances($instances);

        if (!$this->validate($instances)) {
            return;
        }

        foreach ($instances as $instance => $domain) {
            echo "certificate for $domain (instanceId: $instance) ";
            if ($this->updateCertificate($domain, $instance)) {
                echo "updated\n";
            } else {
                echo "failed\n";
            }
        }
    }

    protected function validate($instances): bool
    {
        $valid = true;
        foreach ($instances as $instance => $domain) {
            $path = $this->buildPath($domain);
            if (!is_dir($path)) {
                $valid = false;
                echo "path '$path' for $domain (instanceID: $instance) does not exist\n";
            }
        }
        return $valid;
    }

    protected function normalizeInstances($instances): array
    {
        $result = [];
        foreach ($instances as $item) {
            [$domain, $instance] = explode(':', $item);
            $result[$domain] = $instance;
        }

        return $result;
    }

    protected function updateCertificate(string $domain, string $instance): bool
    {
        $dir = $this->buildPath($domain);
        $chain = "$dir/certificate_full_chain.pem";
        $key = "$dir/private_key.pem";
        exec($this->ycBin." certificate-manager certificate content --chain $chain --key $key --id $instance", $out);
        return is_array($out) && trim($out[3]) == '-----BEGIN CERTIFICATE-----';
    }

    protected function echo($msg): void
    {
        echo date('d-m-Y H:i:s') .' ' . $msg . PHP_EOL;
    }

    protected function buildPath($domain): string
    {
        return $this->sslDir .'/'.$domain;
    }
}

$yc = new YcSsl();
$yc->handle($argv);
