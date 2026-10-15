package com.acme;
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @GetMapping("/{id}")
    public Order get(@PathVariable Long id) { return null; }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {}

    @RequestMapping(value = "/search", method = RequestMethod.POST)
    public List<Order> search() { return null; }
}
