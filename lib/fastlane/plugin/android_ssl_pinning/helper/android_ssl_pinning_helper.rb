require 'fastlane_core/ui/ui'
require 'openssl'
require 'base64'
require 'date'

module Fastlane
  module Helper
    class AndroidSslPinningHelper
      def self.get_certificate_info(domain_name)
        tcp_client = TCPSocket.new(domain_name, 443)
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_client, ssl_context)
        ssl_socket.hostname = domain_name
        ssl_socket.connect
        certificate = ssl_socket.peer_cert
        public_key = certificate.public_key

        # Extract the desired information
        domain = certificate.subject.to_a.find { |name, _, _| name == 'CN' }[1]
        expiration_date = Date.parse(certificate.not_after.to_s)

        digest = OpenSSL::Digest.new('SHA256')
        fingerprint = digest.hexdigest(public_key.to_der)
        fingerprint = Base64.strict_encode64([fingerprint].pack('H*'))
        

        # Create and return the certificate object
        certificate_obj = {
          "domain" => domain.sub(/^\*\./, ''),
          "is_wildcard" => domain.start_with?('*'),
          "expiration_date" => expiration_date,
          "fingerprint" => fingerprint
        }

        ssl_socket.close
        tcp_client.close

        certificate_obj
      end
    end
  end
end
