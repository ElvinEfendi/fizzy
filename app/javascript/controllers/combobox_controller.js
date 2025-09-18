import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = [ "label", "item" ]
  static values = { selectPropertyName: { type: String, default: "aria-checked" } }

  connect() {
    this.labelTarget.textContent = this.#selectedLabel
  }

  change(event) {
    const item = event.target.closest("[role='checkbox']")
    if (item) {
      this.#selectedItem = item
    }
  }

  get #selectedLabel() {
    const label = this.#selectedItem.querySelector("[data-combobox-label]")
    return label.dataset.comboboxLabel
  }

  get #selectedItem() {
    return this.itemTargets.find(item => item.getAttribute(this.selectPropertyNameValue) === "true")
  }

  set #selectedItem(item) {
    this.#clearSelection()
    item.setAttribute(this.selectPropertyNameValue, "true")
    this.labelTarget.textContent = this.#selectedLabel
  }

  #clearSelection() {
    this.itemTargets.forEach(target => {
      target.setAttribute(this.selectPropertyNameValue, "false")
    })
  }
}
