class ApplicationController < ActionController::API                                
    def authenticate_token                                                           
      render json: { status: 401, message: 'Unauthorized' } unless decode_token(bearer_token)
    end                                                                              
  
    def bearer_token                                                                 
      header = request.env['HTTP_AUTHORIZATION']                                     
      pattern = /^Bearer /                                                           
      header.gsub(pattern, '') if header && header.match(pattern)                    
    end                                                                              
  
    def decode_token(token_input)                                                    
      JWT.decode(token_input, ENV['JWT_SECRET'], true)                                           
    rescue                                                                           
      render json: { status: 401, message: 'Unauthorized' }                          
    end   
    
    def get_current_user                                                           
        return if !bearer_token                                                      
        decoded_jwt = decode_token(bearer_token)                                     
        User.find(decoded_jwt[0]["user"]["id"])                                                     
    end   
         
    def authorize_user
        puts "AUTHORIZE USER"
        puts "user id: #{get_current_user.id}"
        puts "params: #{params[:id]}"                                                             
        render json: { status: 401, message: "Unauthorized" } unless get_current_user.id == params[:id].to_i                                                         
      end
  end
