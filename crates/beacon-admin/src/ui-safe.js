// External API data is text. Keep event handlers as closures, never markup.
function appendText(parent, className, value) {
    const element = document.createElement('div');
    element.className = className;
    element.textContent = String(value);
    parent.appendChild(element);
    return element;
}

function appendButton(parent, label, action) {
    const button = document.createElement('button');
    button.className = 'btn btn-secondary btn-sm';
    button.textContent = label;
    button.addEventListener('click', action);
    parent.appendChild(button);
}
