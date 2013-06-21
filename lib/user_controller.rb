require 'omf_rc'
require 'omf_common'
require 'yaml'

$stdout.sync = true


@config = YAML.load_file('../etc/configuration.yaml')
@auth = @config[:auth]
@xmpp = @config[:xmpp]

module OmfRc::ResourceProxy::UserController
  include OmfRc::ResourceProxyDSL

  register_proxy :userController

  property :users, :default => []

  hook :before_ready do |resource|
    File.open('/etc/passwd', 'r') do |file|
      file.each do |line|
        tmp = line.chomp.split(':')[0]
        resource.property.users << tmp
      end
    end
  end

#   hook :before_create do |controller, new_resource_type, new_resource_opts|
#     controller.property.users.each do |user|
#       if user == new_resource_opts.username
#         raise "user '#{new_resource_opts.username}' already exists"
#       end
#     end
#   end

  hook :after_create do |controller, user|
    controller.property.users << user.property.username
  end

  request :users do |res|
    #puts "Returing #{res.property.users.to_s}"
    res.property.users
  end
end

module OmfRc::ResourceProxy::User
  include OmfRc::ResourceProxyDSL

  require 'omf_common/exec_app'

  register_proxy :user, :create_by => :userController

  utility :common_tools
  utility :platform_tools

  property :username
  property :app_id, :default => nil
  property :binary_path, :default => '/usr/sbin/useradd'
  property :map_err_to_out, :default => false

  configure :cert do |res, value|
    #puts "CERTIFICATE #{value.inspect}"
    path = "/home/#{res.property.username}/.omf/"
    unless File.directory?(path)#create the directory if it doesn't exist (it will never exist)
      FileUtils.mkdir_p(path)
    end

    File.write("#{path}/cert.pem", value)
  end

  configure :auth_keys do |res, value|

  end

  #hook :before_ready do |user|
    #define_method("on_app_event") { |*args| process_event(self, *args) }
  #end

  hook :after_initial_configured do |user|
    user.property.app_id = user.hrn.nil? ? user.uid : user.hrn

    ExecApp.new(user.property.app_id, user.build_command_line, user.property.map_err_to_out) do |event_type, app_id, msg|
      user.process_event(user, event_type, app_id, msg)
    end
  end

  # This method processes an event coming from the application instance, which
  # was started by this Resource Proxy (RP). It is a callback, which is usually
  # called by the ExecApp class in OMF
  #
  # @param [AbstractResource] res this RP
  # @param [String] event_type the type of event from the app instance
  #                 (STARTED, DONE.OK, DONE.ERROR, STDOUT, STDERR)
  # @param [String] app_id the id of the app instance
  # @param [String] msg the message carried by the event
  #
  def process_event(res, event_type, app_id, msg)
      logger.info "App Event from '#{app_id}' - #{event_type}: '#{msg}'"
      if event_type == 'EXIT'
        if msg == 0 #only when user creation succeeds, create a new public key and save it to /home/username/.ssh/
                    #then inform with the appropriate msg, and give the pub key
          key = OpenSSL::PKey::RSA.new(2048)

          pub_key = key.public_key

          path = "/home/#{res.property.username}/.ssh/"
          unless File.directory?(path)#create the directory if it doesn't exist (it will never exist)
            FileUtils.mkdir_p(path)
          end

          File.write("#{path}/pub_key.pem", pub_key.to_pem)
          File.write("#{path}/key.pem", key.to_pem)

          res.inform(:status, {
                        status_type: 'APP_EVENT',
                        event: event_type.to_s.upcase,
                        app: app_id,
                        exit_code: msg,
                        msg: msg,
                        uid: res.uid, # do we really need this? Should be identical to 'src'
                        pub_key: pub_key
                      }, :ALL)
        else #if msg!=0 then the application failed to complete
          path = "/home/#{res.property.username}/.ssh/"
          if File.exists?("#{path}/pub_key.pem") && File.exists?("#{path}/key.pem")#if keys exist just read the pub_key for the inform
            file = File.open("#{path}/pub_key.pem", "rb")
            pub_key = file.read
            file.close
          else #if keys do not exist create them and then inform
            key = OpenSSL::PKey::RSA.new(2048)

            pub_key = key.public_key

            path = "/home/#{res.property.username}/.ssh/"
            unless File.directory?(path)#create the directory if it doesn't exist (it will never exist)
              FileUtils.mkdir_p(path)
            end

            File.write("#{path}/pub_key.pem", pub_key.to_pem)
            File.write("#{path}/key.pem", key.to_pem)
          end
          res.inform(:status, {
                        status_type: 'APP_EVENT',
                        event: event_type.to_s.upcase,
                        app: app_id,
                        exit_code: msg,
                        msg: msg,
                        uid: res.uid, # do we really need this? Should be identical to 'src'
                        pub_key: pub_key
                      }, :ALL)
        end
      else
        res.inform(:status, {
                      status_type: 'APP_EVENT',
                      event: event_type.to_s.upcase,
                      app: app_id,
                      msg: msg,
                      uid: res.uid
                    }, :ALL)
      end
  end

  # Build the command line, which will be used to add a new user.
  #
  work('build_command_line') do |res|
    cmd_line = "env -i " # Start with a 'clean' environment
    cmd_line += res.property.binary_path + " " # the /usr/sbin/useradd
    cmd_line += res.property.username + " -m"  # the username and -m for adding folder
    cmd_line
  end
end

entity_cert = File.expand_path(@auth[:entity_cert])
entity_key = File.expand_path(@auth[:entity_key])
entity = OmfCommon::Auth::Certificate.create_from_x509(File.read(entity_cert), File.read(entity_key))

trusted_roots = File.expand_path(@auth[:root_cert_dir])

OmfCommon.init(:development, communication: { url: "xmpp://#{@xmpp[:username]}:#{@xmpp[:password]}@#{@xmpp[:server]}", auth: {} }) do
  OmfCommon.comm.on_connected do |comm|
    OmfCommon::Auth::CertificateStore.instance.register_default_certs(trusted_roots)
    OmfCommon::Auth::CertificateStore.instance.register(entity, OmfCommon.comm.local_topic.address)
    OmfCommon::Auth::CertificateStore.instance.register(entity)

    info "UserController >> Connected to XMPP server"
    userContr = OmfRc::ResourceFactory.create(:userController, { uid: 'userController', certificate: entity })
    comm.on_interrupted { userContr.disconnect }
  end
end
