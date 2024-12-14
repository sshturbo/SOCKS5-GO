# SOCKS5-GO

Este é um servidor SOCKS5 escrito em Go, com suporte a autenticação, TLS, e manipulação de pacotes UDP e TCP.

## Funcionalidades

- Autenticação com nome de usuário e senha
- Suporte para TCP e UDP
- Conexões seguras com TLS
- Limpeza automática de sessões UDP inativas
- Resolução de DNS com cache
- Registro de pacotes recebidos

## Instalação

Para instalar o SOCKS5-GO, use o comando abaixo:

```sh
go get github.com/seu-usuario/SOCKS5-GO
```

## Configuração

A configuração do servidor é feita através de um arquivo `config.yaml`. Abaixo está um exemplo de configuração:

```yaml
address: "0.0.0.0:1087"        # Endereço para escutar conexões
username: "root"               # Nome de usuário para autenticação
password: "102030"          # Senha para autenticação
blocked_ips:
  - "192.168.1.100"
  - "10.0.0.200"               # Lista de IPs bloqueados
enable_tls: false              # Habilitar TLS para conexões seguras
cert_file: "server.crt"        # Caminho para o arquivo de certificado TLS
key_file: "server.key"         # Caminho para o arquivo de chave TLS
rate_limit: 10                 # Limite de taxa para conexões
max_packet_size: 4096          # Tamanho máximo do pacote em bytes
cleanup_interval: 10           # Intervalo de limpeza em minutos
session_timeout: 30            # Tempo de inatividade para sessão expirar em minutos
log_level: "debug"             # Nível de log: "debug", "info", "warn", "error"
log_format: "json"             # Formato do log: "text" ou "json"
```

## Uso

Exemplo de uso básico:

```go
package main

import (
    "log"
    "github.com/seu-usuario/SOCKS5-GO"
    "github.com/spf13/viper"
)

func main() {
    // Carregar configuração do arquivo config.yaml
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    if err := viper.ReadInConfig(); err != nil {
        log.Fatalf("erro ao ler o arquivo de configuração: %v", err)
    }

    var cfg socks5.Config
    if err := viper.Unmarshal(&cfg); err != nil {
        log.Fatalf("erro ao processar configuração: %v", err)
    }

    // Criar servidor SOCKS5 com a configuração carregada
    server, err := socks5.New(&cfg)
    if err != nil {
        log.Fatal(err)
    }

    // Iniciar o servidor SOCKS5
    if err := server.ListenAndServe("tcp", cfg.Address); err != nil {
        log.Fatal(err)
    }
}
```

## Contribuição

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. Faça commit das suas alterações (`git commit -am 'Adiciona nova feature'`)
4. Faça push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para mais detalhes.