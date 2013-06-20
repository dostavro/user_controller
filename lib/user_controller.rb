require 'omf_rc'
require 'omf_common'

$stdout.sync = true


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

  hook :before_create do |controller, new_resource_type, new_resource_opts|
    controller.property.users.each do |user|
      if user == new_resource_opts.username
        raise "user '#{new_resource_opts.username}' already exists"
      end
    end
  end

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
    puts "CERTIFICATE #{value.inspect}"
    #TODO
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
          key = OpenSSL::PKey::RSA.new(2048)

          pub_key = key.public_key

          path = "/home/#{res.property.username}/.ssh/"
          puts path
          unless File.directory?(path)#create the directory if it doesn't exist (it will never exist)
            FileUtils.mkdir_p(path)
          end
          File.write("#{path}/pub_key.pem", pub_key.to_pem)
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

  # Build the command line, which will be used to start this app.
  #res
  # This command line will be of the form:
  # "env -i VAR1=value1 ... application_path parameterA valueA ..."
  #
  # The environment variables and the parameters in that command line are
  # taken respectively from the 'environments' and 'parameters' properties of
  # this Application Resource Proxy. If the 'use_oml' property is set, then
  # add to the command line the necessary oml parameters.
  #
  # @return [String] the full command line
  # @!macro work
  work('build_command_line') do |res|
    cmd_line = "env -i " # Start with a 'clean' environment
    cmd_line += res.property.binary_path + " " # the /usr/sbin/useradd
    cmd_line += res.property.username + " -m"  # the username and -m for adding folder
    cmd_line
  end
end

entity = OmfCommon::Auth::Certificate.create_from_x509(File.read("/home/dostavro/.omf/urc.pem"),
                                                       File.read("/home/dostavro/.omf/user_rc_key.pem"))


OmfCommon.init(:development, communication: { url: 'xmpp://alpha:pw@localhost', auth: {} }) do
  OmfCommon.comm.on_connected do |comm|

    OmfCommon::Auth::CertificateStore.instance.register_default_certs("/home/dostavro/.omf/trusted_roots/")
    OmfCommon::Auth::CertificateStore.instance.register(entity, OmfCommon.comm.local_topic.address)
    OmfCommon::Auth::CertificateStore.instance.register(entity)

    info "UserController >> Connected to XMPP server"
    userContr = OmfRc::ResourceFactory.create(:userController, { uid: 'userController', certificate: entity })
    comm.on_interrupted { userContr.disconnect }
  end
end
