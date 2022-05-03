
function reload_button_with_time(time) {

    //document.getElementById("disable_on_click").disabled = true;
    //window.setTimeout(reload_button, time);
}

function reload_button() {
    location.reload();
}

const added_users = []
function add_user_to_list_button(user_username, button_id) {
    
    const index = added_users.indexOf(user_username);
    if (index > -1) {
        added_users.splice(index, 1);
        document.getElementById(button_id).classList.remove("btn-danger");
        document.getElementById(button_id).classList.add("btn-success");
        console.log("Usuario Eliminado")
    } else {
        added_users.push(user_username);
        document.getElementById(button_id).classList.remove("btn-success");
        document.getElementById(button_id).classList.add("btn-danger");
        console.log("Usuario Agregado")
    }

    var text_to_display = "";
    for(let i = 0; i < added_users.length; i++){
        text_to_display += added_users[i] + ", ";
    }
    text_to_display = text_to_display.slice(0,-2)
    document.getElementById("list_users").value=text_to_display;
    
}

let search_value = ""
document.addEventListener("keyup", () => {
    document.getElementById("search-user-field").focus();
    search_value = document.getElementById("search-user-field").value
    var user_buttons = document.getElementsByName("user")

    for(let i = 0;i < user_buttons.length; i++){
        if(user_buttons[i].id.includes(search_value)){
            user_buttons[i].style.display="block"
        }else {
            user_buttons[i].style.display="none"
        }
    }
});

