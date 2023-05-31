require "fastlane/action"
require_relative "../helper/android_ssl_pinning_helper"
require "nokogiri"

module Fastlane
  module Actions
    class AndroidSslPinningAction < Action
      def self.run(params)
        UI.message("👷 Starting SSL Pinning setup")
        if params
          xml_path = params[:xml_path]
          domains = params[:domains]
          
          # Open XML for modification
          doc = File.open(xml_path) { |f| Nokogiri::XML(f) }

          # Remove all <domain-config> elements
          doc.xpath("//network-security-config/domain-config").remove
          
          # Loop every domains param and modify the xml file to add <domain-config> element
          domains.each do |domain|
            certificate_info = Helper::AndroidSslPinningHelper.get_certificate_info(domain)

            # Add elements
            domain_config_element = Nokogiri::XML::Node.new('domain-config', doc)
            
            domain_element = Nokogiri::XML::Node.new("domain", doc)
            domain_element.content = certificate_info["domain"]
            domain_element.set_attribute("includeSubdomains", certificate_info["is_wildcard"] ? "true" : "false")
            
            pinset_element = Nokogiri::XML::Node.new("pin-set", doc)
            pinset_element.set_attribute("expiration", certificate_info["expiration_date"])

            pin_element = Nokogiri::XML::Node.new("pin", doc)
            pin_element.set_attribute("digest", "SHA-256")
            pin_element.content = certificate_info["fingerprint"]

            pinset_element.add_child(pin_element)
            domain_config_element.add_child(domain_element)
            domain_config_element.add_child(pinset_element)
            
            doc.at('//network-security-config').add_child(domain_config_element)
            UI.message("~~> Configured for domain #{domain}")
          end

          File.open(xml_path, 'w') { |file| file.write(doc.to_xml) }
          UI.success("🎉 Successfully setup SSL Pinning")
        end
      end

      def self.description
        "Automaically generate and setup SSL-pinning for Android"
      end

      def self.authors
        ["Phu Hoang"]
      end

      def self.return_value
        # If your method provides a return value, you can describe here what it does
      end

      def self.details
        # Optional:
        ""
      end

      def self.available_options
        [
          FastlaneCore::ConfigItem.new(key: :xml_path,
                                  env_name: "ANDROID_SSL_PINNING_XML_PATH",
                               description: "Path to xml file which use for configure Android network security",
                                  optional: false,
                                      type: String),
          FastlaneCore::ConfigItem.new(key: :domains,
                                        env_name: "ANDROID_SSL_PINNING_DOMAINS",
                                     description: "Path to xml file which use for configure Android network security",
                                        optional: false,
                                            type: Array)
        ]
      end

      def self.is_supported?(platform)
        [:android].include?(platform)
      end
    end
  end
end
