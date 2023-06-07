pub struct SessionData {
    pub state: SessionState,
}

pub enum SessionState {
    LoggedIn,
    Enrolement(EnrolementState),
}

pub enum EnrolementState {}

/*pub fn get_state(mut ) {

}*/
