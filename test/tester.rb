require 'omf_common'

def create_user(controller)

  controller.create(:user, hrn: 'new_user', username: 'aris') do |reply_msg|
    # This reply_msg will be the inform message issued by garage controller
    #
    if reply_msg.success?
      # Since we need to interact with engine's PubSub topic,
      # we call #resource method to construct a topic from the FRCP message content.
      #
      user = reply_msg.resource

      # Because of the asynchronous nature, we need to use this on_subscribed callback
      # to make sure the operation in the block executed only when subscribed to the newly created engine's topic
      user.on_subscribed do
        info ">>> Connected to newly created user #{reply_msg[:hrn]}(id: #{reply_msg[:res_id]})"

      end

      # Then later on, we will ask garage again to release this engine.
      #
      OmfCommon.eventloop.after(5) do
        release_user(controller, user)
      end
    else
      error ">>> Resource creation failed - #{reply_msg[:reason]}"
    end
  end
end

def release_user(controller, user)
  info ">>> Release user"
  # Only parent (garage) can release its child (engine)
  #
  controller.release(user) do |reply_msg|
    info "Engine #{reply_msg[:res_id]} released"
    OmfCommon.comm.disconnect
  end
end

OmfCommon.init(:development, communication: { url: 'xmpp://beta:1234@localhost' }) do
  OmfCommon.comm.on_connected do |comm|
    info "Test script >> Connected to XMPP"

    comm.subscribe('userController') do |controller|
      unless controller.error?
        # Now calling create_engine method we defined, with newly created garage topic object
        #
        create_user(controller)
      else
        error controller.inspect
      end
    end

    OmfCommon.eventloop.after(10) { comm.disconnect }
    comm.on_interrupted { comm.disconnect }
  end
end
