let rand = 0;
let params;
let subj;

window.onload=function(){main();}

function main(){
    subj = sessionStorage.getItem('selSub');
    switch(subj){
        case "security":
            params=solutions;
            break;
        case "queries":
            params=queries;
            break;
        case "fiveObj":
            params=fiveObj;
            break;
        case "newTech":
            params=newTech;
            break;
    }
    shuffQ();
}

function shuffQ(){
    if(params.length==0){
        alert("더 이상 문제가 없습니다.");
        return;
    }
    rand = Math.floor(Math.random()*params.length);
    document.getElementById("view").value = params[rand].answer;
    document.getElementById("answer").innerText = "(정답)";
}
function viewAns(){
    document.getElementById("answer").innerText = params[rand].question;
}
function exceptQ(){
    params.splice(rand,1);
    shuffQ();
    //for(i in params) console.log(params[i].question);
}