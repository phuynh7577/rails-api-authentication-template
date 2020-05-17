class UsersController < ApplicationController
  before_action :set_user, only: [:show, :update, :destroy]
  before_action :authenticate_token, except: [:login, :create]
  before_action :authorize_user, except: [:login, :create, :index]

  # GET /users
  def index
    @users = User.all

    render json: @users
  end

  # GET /users/1
  def show
    render json: get_current_user
  end

  # POST /users
  def create
    @user = User.new(user_params)

    if @user.save
      user = User.find_by(email: params[:user][:email])
      token = create_token(user.id, user.email)
      # render json: @user, status: :created, location: @user
      render json: { status: 201, token: token, user: user }
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /users/1
  def update
    if @user.update(user_params)
      render json: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # DELETE /users/1
  def destroy
    @user.destroy
  end

  # LOGIN /users/login
  def login
    user = User.find_by(email: params[:user][:email])
    if user && user.authenticate(params[:user][:password])
      token = create_token(user.id, user.email)
      render json: {status: 200, token: token, user: user}
    else
      render json: {status: 401, message: "Either your email or password is incorrect."}
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Only allow a trusted parameter "white list" through.
    def user_params
      params.require(:user).permit(:email, :password, :store_name)
    end

    def create_token(id, email)
      JWT.encode(payload(id, email), ENV['JWT_SECRET'], 'HS256')
    end

    def payload(id, email)
      {
        exp: (Time.now + 120.minutes).to_i,
        iat: Time.now.to_i,
        iss: ENV['JWT_ISSUER'],
        user: {
          id: id,
          email: email
        }
      }
    end
end
